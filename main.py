import typer
import yaml
import re
import json
import time
import concurrent.futures
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Iterable
from dataclasses import dataclass, asdict
from functools import lru_cache
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box
from identify import identify
import glob
import fnmatch
import copy

# консоль и cli тут все просто. ладно
console = Console()
app = typer.Typer(add_completion=False)

MAX_FILE_SIZE = 5 * 1024 * 1024  
# ограничиваем размер файла чтобы не читать слишком много вдруг попадется

DETECTORS: Dict[str, Dict[str, Any]] = {}


# карта уровней важности цвета и штрафы дефолтные значения
DEFAULT_SEVERITY_MAP: Dict[str, Dict[str, Any]] = {
    "CRITICAL": {"color": "bold red", "deduction": 40},
    "HIGH": {"color": "orange1", "deduction": 25},
    "MEDIUM": {"color": "yellow", "deduction": 15},
    "LOW": {"color": "blue", "deduction": 5},
    "INFO": {"color": "cyan", "deduction": 0},
}

# загрузка детекторов из yaml если что то не так просто пропускаем
def load_detectors(rules_path: Path) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    try:
        if rules_path.is_file():
            paths: Iterable[Path] = [rules_path]
        else:
            paths = rules_path.glob("*.yaml")
        for p in paths:
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            tag = data.get("target_tag")
            detect = data.get("detect")
            if tag and isinstance(detect, dict):
                result[tag] = detect
    except Exception:
        pass
    return result

def configure_detectors(detectors: Dict[str, Dict[str, Any]]) -> None:
    global DETECTORS
    DETECTORS = detectors or {}

# проверяем yaml по ключам стараемся без лишнего
def _match_yaml_detector(content: str, spec: Dict[str, Any]) -> bool:
    try:
        for doc in yaml.safe_load_all(content):
            if doc is None:
                continue

            def has_required_keys_any(mapping: Dict[str, Any], keys_any: Iterable[str]) -> bool:
                if not isinstance(mapping, dict):
                    return False
                
                for k in keys_any:
                    if k in mapping:
                        return True
                    if k == "on" and True in mapping:
                        return True
                return False

            req_any = spec.get("required_root_keys_any")
            child = spec.get("child_map_any")
            child_list = spec.get("child_list_any")
            root_list_item_keys = spec.get("root_list_item_keys_any")

            
            if isinstance(doc, dict):
                if req_any and isinstance(req_any, (list, tuple, set)):
                    if not has_required_keys_any(doc, req_any):
                        continue
                if child and isinstance(child, dict):
                    root_key = child.get("key")
                    keys_any = child.get("keys_any") or []
                    sub = doc.get(root_key)
                    ok = False
                    if isinstance(sub, dict):
                        for v in sub.values():
                            if isinstance(v, dict) and any(k in v for k in keys_any):
                                ok = True
                                break
                    if not ok:
                        continue
                if child_list and isinstance(child_list, dict):
                    root_key = child_list.get("key")
                    item_keys_any = child_list.get("item_keys_any") or []
                    sub = doc.get(root_key)
                    ok = False
                    if isinstance(sub, list):
                        for it in sub:
                            if isinstance(it, dict) and any(k in it for k in item_keys_any):
                                ok = True
                                break
                    if not ok:
                        continue
                return True

            
            if isinstance(doc, list):
                matched = True
                if req_any and isinstance(req_any, (list, tuple, set)):
                    matched = False
                    for item in doc:
                        if isinstance(item, dict) and has_required_keys_any(item, req_any):
                            matched = True
                            break
                if not matched:
                    continue
                if root_list_item_keys and isinstance(root_list_item_keys, (list, tuple, set)):
                    ok = False
                    for item in doc:
                        if isinstance(item, dict) and any(k in item for k in root_list_item_keys):
                            ok = True
                            break
                    if not ok:
                        continue
                if child and isinstance(child, dict):
                    root_key = child.get("key")
                    keys_any = child.get("keys_any") or []
                    ok = False
                    for item in doc:
                        if not isinstance(item, dict):
                            continue
                        sub = item.get(root_key)
                        if isinstance(sub, dict):
                            for v in sub.values():
                                if isinstance(v, dict) and any(k in v for k in keys_any):
                                    ok = True
                                    break
                        if ok:
                            break
                    if not ok:
                        continue
                return True
    except Exception:
        return False
    return False

# собираем теги по пути и по содержимому иногда это спасает от ложных определений
def _apply_detectors(path: Path, base_tags: Set[str]) -> Set[str]:
    tags = set(base_tags)
    if not DETECTORS:
        return tags
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        content = ""
    for tag, spec in DETECTORS.items():
        if not isinstance(spec, dict):
            continue
        
        path_match = False
        try:
            path_globs = spec.get("path_glob_any") or []
            if isinstance(path_globs, (list, tuple, set)) and path_globs:
                pstr = str(path.as_posix())
                for pat in path_globs:
                    if not isinstance(pat, str):
                        continue
                    if any(ch in pat for ch in "*?[]"):
                        if fnmatch.fnmatch(pstr, pat) or fnmatch.fnmatch(pstr, f"*/{pat}"):
                            path_match = True
                            break
                    else:
                        if pat in pstr:
                            path_match = True
                            break
        except Exception:
            path_match = False

        if path_match:
            tags.add(tag)
            continue

        yaml_spec = spec.get("yaml")
        if yaml_spec and isinstance(yaml_spec, dict):
            if content and _match_yaml_detector(content, yaml_spec):
                tags.add(tag)
    return tags

def get_file_tags(file_path_str: str) -> Set[str]:
    try:
        base = set(identify.tags_from_path(file_path_str))
        return _apply_detectors(Path(file_path_str), base)
    except Exception as e:
        print(f"Error getting tags for {file_path_str}: {e}", file=sys.stderr)
        return set()

# парсим подавления прямо из текста иногда люди пишут по разному
def _parse_suppressions(content: str):
    ignore_all_file = False
    ignore_ids_file: Set[str] = set()
    ignore_lines_all: Set[int] = set()
    ignore_lines_by_id: Dict[str, Set[int]] = {}

    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if '# scan-ignore-file' in line:
            m = re.search(r'#\s*scan-ignore-file\s*:\s*([^#]+)', line)
            if m:
                ids = [x.strip() for x in m.group(1).split(',') if x.strip()]
                ignore_ids_file.update(ids)
            else:
                ignore_all_file = True
        if '# scan-ignore' in line:
            m = re.search(r'#\s*scan-ignore\s*:\s*([^#]+)', line)
            if m:
                ids = [x.strip() for x in m.group(1).split(',') if x.strip()]
                for rid in ids:
                    ignore_lines_by_id.setdefault(rid, set()).add(i)
            else:
                ignore_lines_all.add(i)

    return ignore_all_file, ignore_ids_file, ignore_lines_all, ignore_lines_by_id

# модель одной находки поля простые потом можно расширить
@dataclass
class Finding:
    file: str
    line: Any
    rule_id: str
    severity: str
    description: str
    tag: str
    deduction: int
    code: str = ""
    cvss: Any = None
    cwe: str = ""
    link: str = ""

# кэшируем чтобы не дергать определение типов слишком часто
@lru_cache(maxsize=1024)
def _cached_get_file_tags(file_path: str) -> Set[str]:
    
    return get_file_tags(file_path)

# основной движок сканера делает всю работу тут
class ScannerEngine:
    def __init__(self, rules_path: Path, lang: str = "ru"):
        self.rules_path = rules_path
        self.lang = lang
        self.rules_by_tag: Dict[str, List[Dict]] = {}
        
        self.severity_config: Dict[str, Dict[str, Any]] = copy.deepcopy(DEFAULT_SEVERITY_MAP)
        self.rule_overrides: Dict[str, Set[str]] = {}
        self._load_rules()

    # грузим правила из yaml сливаем штрафы готовим overrides иногда пустые файлы
    def _load_rules(self):
        paths = [self.rules_path] if self.rules_path.is_file() else list(self.rules_path.glob("*.yaml"))
        
        if not paths:
            raise ValueError(f"No rules found at {self.rules_path}")

        for path in paths:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if not data: continue
                    
                    meta = data.get('metadata', {})
                    
                    meta_map = meta.get('severity_map', {})
                    if isinstance(meta_map, dict):
                        for sev, opts in meta_map.items():
                            if not isinstance(opts, dict):
                                continue
                            if 'deduction' in opts:
                                current = self.severity_config.setdefault(
                                    sev,
                                    {
                                        "color": DEFAULT_SEVERITY_MAP.get(sev, {}).get("color", "white"),
                                        "deduction": 0,
                                    },
                                )
                                current['deduction'] = opts['deduction']
                    
                    tag = data.get('target_tag')
                    rules_raw = data.get('rules', [])
                    
                    for r in rules_raw:
                        rid = r.get('id')
                        if not rid:
                            continue
                        ovs = r.get('overrides') or []
                        if isinstance(ovs, (list, tuple, set)):
                            self.rule_overrides.setdefault(str(rid), set()).update(str(x) for x in ovs)
                    rules = self._compile_rules(rules_raw)
                    
                    if tag not in self.rules_by_tag:
                        self.rules_by_tag[tag] = []
                    self.rules_by_tag[tag].extend(rules)
            except Exception as e:
                console.print(f"[yellow]⚠ Ошибка загрузки {path.name}: {e}[/yellow]")
        
        try:
            detectors = load_detectors(self.rules_path)
            configure_detectors(detectors)
        except Exception:
            pass

    # компилируем регулярные выражения иначе будет медленно
    def _compile_rules(self, rules: List[Dict]) -> List[Dict]:
        for rule in rules:
            if rule.get('type') == 'regex':
                rule['compiled_pattern'] = re.compile(rule['pattern'], re.MULTILINE | re.IGNORECASE | re.DOTALL)
        return rules

    # сканируем один файл по активным тегам и применяем подавления
    def scan_file(self, file_path_str: str) -> List[Finding]:
        file_path = Path(file_path_str)
        findings = []
        try:
            if not file_path.exists() or file_path.stat().st_size > MAX_FILE_SIZE:
                return []

            tags = _cached_get_file_tags(file_path_str)
            
            active_tags = tags.intersection(self.rules_by_tag.keys())
            
            if not active_tags:
                return []

            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not content:
                return []

            ignore_all_file, ignore_ids_file, ignore_lines_all, ignore_lines_by_id = _parse_suppressions(content)

            content_lines: Optional[List[str]] = None

            for tag in active_tags:
                for rule in self.rules_by_tag[tag]:
                    rtype = rule.get('type', 'contains')
                    pattern = rule.get('pattern')
                    
                    found_lines: List[Tuple[Any, str]] = [] 

                    if rtype == 'not_contains':
                        if pattern not in content:
                            found_lines = [(0, "")] 
                    elif rtype == 'contains':
                        if pattern in content:
                            if content_lines is None: content_lines = content.splitlines()
                            for i, line in enumerate(content_lines, 1):
                                if pattern in line:
                                    found_lines.append((i, line.strip()))
                    elif rtype == 'regex':
                        mo = rule['compiled_pattern'].search(content)
                        if mo:
                            if content_lines is None:
                                content_lines = content.splitlines()
                            for i, line in enumerate(content_lines, 1):
                                if rule['compiled_pattern'].search(line):
                                    found_lines.append((i, line.strip()))
                            
                            if not found_lines:
                                
                                start_pos = mo.start()
                                
                                prefix = content[:start_pos]
                                line_no = prefix.count('\n') + 1
                                code_line = content_lines[line_no - 1].strip() if content_lines and 1 <= line_no <= len(content_lines) else ""
                                found_lines.append((line_no, code_line))

                    for ln, code_text in found_lines:
                        
                        if ignore_all_file:
                            continue
                        if rule.get('id') in ignore_ids_file:
                            continue
                        if isinstance(ln, int) and ln > 0:
                            if ln in ignore_lines_all:
                                continue
                            by_id = ignore_lines_by_id.get(rule.get('id'), set())
                            if ln in by_id:
                                continue
                        findings.append(self._create_finding(rule, file_path_str, ln, tag, code_text))
            
            
            if findings:
                present = {f.rule_id for f in findings if f.rule_id}
                suppress_ids: Set[str] = set()
                for rid in present:
                    for sid in self.rule_overrides.get(str(rid), set()):
                        if sid in present:
                            suppress_ids.add(sid)
                if suppress_ids:
                    findings = [f for f in findings if f.rule_id not in suppress_ids]

            return findings
        except Exception as e:
            
            print(f"Error scanning {file_path_str}: {e}", file=sys.stderr)
            return []

    # собираем объект результата стараемся не падать
    def _create_finding(self, rule: Dict, file: str, line: Any, tag: str, code: str) -> Finding:
        sev = rule.get('severity', 'INFO')
        cvss = rule.get('cvss')
        if cvss is None:
            default_cvss = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 0.0}
            cvss = default_cvss.get(str(sev).upper(), 0.0)
        cwe_val = rule.get('cwe')
        if isinstance(cwe_val, (list, tuple)):
            cwe_str = ", ".join(str(x) for x in cwe_val)
        else:
            cwe_str = str(cwe_val) if cwe_val is not None else ""
        
        link = ""
        ref = rule.get('link') or rule.get('reference')
        if isinstance(ref, str):
            link = ref.strip()
        else:
            refs = rule.get('references')
            if isinstance(refs, (list, tuple)):
                for r in refs:
                    if isinstance(r, str) and (r.startswith('http://') or r.startswith('https://')):
                        link = r.strip()
                        break
        return Finding(
            file=file,
            
            line="—" if line in [0, "File"] else line,
            rule_id=rule.get('id'),
            severity=sev,
            description=rule.get('description', {}).get(self.lang, "No description"),
            tag=tag,
            deduction=self.severity_config.get(sev, {}).get('deduction', 0),
            code=code,
            cvss=cvss,
            cwe=cwe_str,
            link=link
        )


# воркер держит локальный движок чтобы процессы не создавали его каждый раз
worker_engine: Optional[ScannerEngine] = None

def init_worker(rules_path: Path, lang: str):
    global worker_engine
    worker_engine = ScannerEngine(rules_path, lang)

    # обертка для executor возвращаем список находок
def worker_task(file_path: str) -> List[Finding]:
    return worker_engine.scan_file(file_path)



@app.command()
# основная команда CLI с параметрами сканирования
def scan(
    
    paths: List[Path] = typer.Argument(..., help="Paths to scan"),
    rules_dir: Path = typer.Option(Path("rules"), "--rules", "-r"),
    rule_file: Optional[Path] = typer.Option(None, "--rule-file", "-f"),
    lang: str = typer.Option("ru", "--lang", "-l"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    threads: int = typer.Option(4, "--threads", "-t"),
    sort_by: str = typer.Option("severity", "--sort-by", "-s", help="severity|file"),
    hide_low_info: bool = typer.Option(False, "--hide-low-info", "-m", help="Скрыть LOW и INFO из вывода"),
    min_severity: str = typer.Option("INFO", "--min-severity", help="Минимальный уровень для показа: CRITICAL|HIGH|MEDIUM|LOW|INFO")
):

    start_time = time.perf_counter()
    actual_rules_path = rule_file if rule_file else rules_dir
    
    try:
        ui_engine = ScannerEngine(actual_rules_path, lang)
    except Exception as e:
        console.print(f"[bold red]Критическая ошибка:[/bold red] {e}")
        raise typer.Exit(1)

    ignore_set = {'.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build'}
    
    
    raw_files = []
    for p in paths:
        if p.exists():
            if p.is_file():
                raw_files.append(str(p))
            elif p.is_dir():
                raw_files.extend([
                    str(f) for f in p.rglob('*') 
                    if f.is_file() and not any(x in f.parts for x in ignore_set)
                ])
        else:
            matches = [Path(m) for m in glob.glob(str(p))]
            for m in matches:
                if m.is_file():
                    raw_files.append(str(m))
                elif m.is_dir():
                    raw_files.extend([
                        str(f) for f in m.rglob('*')
                        if f.is_file() and not any(x in f.parts for x in ignore_set)
                    ])
    
    
    # убираем дубликаты вдруг файлы и папки пересеклись
    files = sorted(set(raw_files))

    if not files:
        console.print("[yellow]⚠ Файлы для сканирования не найдены.[/yellow]")
        return

    
    
    # печатаем план чтобы видеть какие теги и что активно (первые 80 файлов для краткости)
    plan_table = Table(box=box.SIMPLE, header_style="bold cyan", border_style="bright_black", expand=True, title="План сканирования")
    plan_table.add_column("File", style="green")
    plan_table.add_column("Base", style="dim", no_wrap=True, overflow="ellipsis")
    plan_table.add_column("Detected", style="magenta", no_wrap=True, overflow="ellipsis")
    plan_table.add_column("Active", style="yellow", no_wrap=True, overflow="ellipsis")

    
    MAX_PREVIEW = 80
    showed = 0
    rule_tags = set(ui_engine.rules_by_tag.keys())
    for fp in files[:MAX_PREVIEW]:
        try:
            base = set(identify.tags_from_path(fp))
        except Exception:
            base = set()
        det = get_file_tags(fp)
        derived = sorted(list(det - base))
        active = sorted(list(det.intersection(rule_tags)))
        plan_table.add_row(fp, ", ".join(sorted(base)), ", ".join(derived), ", ".join(active))
        showed += 1

    console.print(plan_table)
    if len(files) > showed:
        console.print(f"[dim]Показаны первые {showed} из {len(files)} файлов...[/dim]")

    all_findings: List[Finding] = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Анализ...", total=len(files))
        
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=threads, 
            initializer=init_worker, 
            initargs=(actual_rules_path, lang)
        ) as executor:
            futures = [executor.submit(worker_task, f) for f in files]
            for future in concurrent.futures.as_completed(futures):
                all_findings.extend(future.result())

    duration = time.perf_counter() - start_time
    
    # считаем примерную оценку по cvss: средний максимум CVSS по файлам
    if all_findings:
        max_cvss_by_file: Dict[str, float] = {}
        for f in all_findings:
            try:
                val = float(f.cvss) if f.cvss is not None else 0.0
            except Exception:
                val = 0.0
            prev = max_cvss_by_file.get(f.file, 0.0)
            if val > prev:
                max_cvss_by_file[f.file] = val
        if max_cvss_by_file:
            avg_max_cvss = sum(max_cvss_by_file.values()) / len(max_cvss_by_file)
            score = max(0, 100 - int(round(avg_max_cvss * 10)))
        else:
            score = 100
    else:
        score = 100  

    
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    thr = 2 if hide_low_info else severity_order.get(str(min_severity).upper(), 4)
    display_findings = [f for f in all_findings if severity_order.get(str(f.severity).upper(), 99) <= thr]
    hidden_count = len(all_findings) - len(display_findings)

    
    if display_findings:
        

        
        sort_key_sev = lambda x: (severity_order.get(str(x.severity).upper(), 99), str(x.file), x.line if isinstance(x.line, int) else 10**9)
        if str(sort_by).lower() == "file":
            groups: Dict[str, List[Finding]] = {}
            for it in display_findings:
                groups.setdefault(it.file, []).append(it)
            for fname in sorted(groups.keys()):
                table = Table(box=box.ROUNDED, header_style="bold cyan", border_style="bright_black", expand=True, title=fname)
                table.add_column("Level", justify="center")
                table.add_column("Line", justify="center", style="yellow")
                table.add_column("Tag", style="magenta")
                table.add_column("ID", justify="center", style="dim")
                table.add_column("CVSS", justify="center", style="cyan")
                table.add_column("CWE", justify="center", style="cyan")
                table.add_column("Description")

                items = sorted(groups[fname], key=sort_key_sev)
                from rich.markup import escape
                for f in items:
                    style = ui_engine.severity_config.get(f.severity, {}).get('color', 'white')
                    desc_with_code = f.description
                    if f.code:
                        desc_with_code += f"\n>>> {escape(f.code)}"
                    cvss_disp = "" if f.cvss is None else str(f.cvss)
                    cwe_disp = f.cwe or ""
                    id_cell = f.rule_id if not f.link else f"[link={f.link}]{escape(f.rule_id)}[/link]"
                    row = [
                        f"[{style}]{f.severity}[/{style}]",
                        str(f.line),
                        f.tag,
                        id_cell,
                        cvss_disp,
                        cwe_disp,
                        desc_with_code,
                    ]
                    table.add_row(*row)
                console.print(table)
        else:
            items = sorted(display_findings, key=sort_key_sev)
            table = Table(box=box.ROUNDED, header_style="bold cyan", border_style="bright_black", expand=True)
            table.add_column("Level", justify="center")
            table.add_column("File", style="green")
            table.add_column("Line", justify="center", style="yellow")
            show_tag = len(files) > 1
            if show_tag:
                table.add_column("Tag", style="magenta")
            table.add_column("ID", justify="center", style="dim")
            table.add_column("CVSS", justify="center", style="cyan")
            table.add_column("CWE", justify="center", style="cyan")
            table.add_column("Description")

            from rich.markup import escape
            for f in items:
                style = ui_engine.severity_config.get(f.severity, {}).get('color', 'white')
                desc_with_code = f.description
                if f.code:
                    desc_with_code += f"\n>>> {escape(f.code)}"
                row = [f"[{style}]{f.severity}[/{style}]", f.file, str(f.line)]
                if show_tag:
                    row.append(f.tag)
                cvss_disp = "" if f.cvss is None else str(f.cvss)
                cwe_disp = f.cwe or ""
                id_cell = f.rule_id if not f.link else f"[link={f.link}]{escape(f.rule_id)}[/link]"
                row.extend([id_cell, cvss_disp, cwe_disp, desc_with_code])
                table.add_row(*row)
            console.print(table)
    else:
        console.print(Panel("[bold green]✔ Уязвимостей не обнаружено[/bold green]", border_style="green"))

    
    # финальная сводка по уровням для панели
    order_names = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: Dict[str, int] = {k: 0 for k in order_names}
    for f in display_findings:
        key = str(f.severity).upper()
        if key in counts:
            counts[key] += 1
    summary_line = " | ".join([f"{sev}: {counts[sev]}" for sev in order_names])

    score_color = "green" if score > 85 else "yellow" if score > 60 else "red"
    panel_body = (
        f"{summary_line}\n"
        f"Файлов: {len(files)} | Время: {duration:.2f}s | Оценка: [{score_color}][bold]{score}/100[/bold][/{score_color}]"
    )
    console.print(Panel(panel_body, title="Итог", border_style=score_color))

    if output:
        res = {"score": score, "findings": [asdict(f) for f in all_findings]}
        output.write_text(json.dumps(res, ensure_ascii=False, indent=4))

if __name__ == "__main__":
    app()
