"""Report figures from a stored agentic evaluation: SVG written here, PNG rendered by headless Edge or Chrome.

    python scripts/evaluation/make_report_figures.py [evaluation folder]

Default folder: the final 20-run evaluation (20261027_144751). Output: docs/figures/. Standard library only.
"""
from html import escape
from pathlib import Path
from statistics import mean
import json
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
EVALUATIONS = ROOT / 'cis_compliance_dashboard_prototype' / 'data' / 'agentic_evaluations'
OUT = ROOT / 'docs' / 'figures'
LIMIT = 600  # NFR06: each phase within ten minutes.

SURFACE, INK, INK_2, MUTED, GRID = '#fcfcfb', '#0b0b0b', '#52514e', '#8a8984', '#e4e3df'
# One fixed colour per agent in every figure (validated as stacked neighbours, light mode).
AGENT = {'Orchestrator': '#2a78d6', 'Scanner': '#eb6834', 'Analysis': '#1baf7a', 'Remediation': '#6250d6'}
LONG = {'Orchestrator': 'AI Agent Orchestrator (own requests)', 'Scanner': 'Scanner Agent',
        'Analysis': 'Analysis Agent', 'Remediation': 'Remediation Agent'}
SCENARIOS = {'lab': 'Lab state', 'error_gap': 'Collection error', 'drift': 'Drift (regression)',
             'changed_after_approval': 'Changed after approval', 'channel_drop': 'Channel drop'}
PHASES = {'assessment': ('Assessment round', ('Scanner', 'Analysis', 'Orchestrator')),
          'remediation': ('Remediation phase', ('Remediation', 'Scanner', 'Orchestrator'))}


def split(phase):
    """Seconds per agent; the Orchestrator's own share is the phase time not spent in its delegated agents."""
    parts = dict.fromkeys(AGENT, 0.0)
    for agent in phase['agents']:
        if agent['agent'] != 'AI Agent Orchestrator':
            parts[agent['agent'].split()[0]] += agent['seconds']
    parts['Orchestrator'] = max(0.0, phase['seconds'] - sum(parts.values()))
    return parts


def phase_times(rows):
    figure = {}
    for phase in PHASES:
        figure[phase] = []
        for scenario, label in SCENARIOS.items():
            runs = [r[phase] for r in rows if r['scenario'] == scenario]
            if not runs:
                continue
            totals = [run['seconds'] for run in runs]
            splits = [split(run) for run in runs]
            figure[phase].append(dict(label=label, runs=len(runs), mean=mean(totals), low=min(totals), high=max(totals),
                                      parts={a: mean(s[a] for s in splits) for a in AGENT}))
    return figure


def bar(x, y, width, height, colour, round_end):
    if not round_end or width < 8:
        return f'<rect x="{x:.1f}" y="{y}" width="{max(width, 0):.1f}" height="{height}" fill="{colour}"/>'
    r = 4  # Rounded data end only; the baseline end stays square.
    return (f'<path d="M{x:.1f},{y} h{width - r:.1f} a{r},{r} 0 0 1 {r},{r} v{height - 2 * r} a{r},{r} 0 0 1 -{r},{r} '
            f'h-{width - r:.1f} z" fill="{colour}"/>')


def phase_figure(data, runs, source):
    width, left, right, row, bar_h = 920, 190, 70, 34, 20
    scale = (width - left - right) / LIMIT
    y, body = 112, []
    legend_x = left
    for agent in AGENT:  # Legend: swatch plus name in text ink.
        body.append(f'<rect x="{legend_x}" y="78" width="12" height="12" rx="2" fill="{AGENT[agent]}"/>'
                    f'<text x="{legend_x + 18}" y="88" class="legend">{escape(LONG[agent])}</text>')
        legend_x += 18 + 7.2 * len(LONG[agent]) + 22
    for phase, (title, order) in PHASES.items():
        body.append(f'<text x="16" y="{y + 14}" class="panel">{title}</text>')
        y += 30
        top, marks = y, []
        for item in data[phase]:
            marks.append(f'<text x="{left - 12}" y="{y + bar_h / 2 + 5}" class="label" text-anchor="end">'
                         f'{escape(item["label"])}</text>')
            x = left
            for n, agent in enumerate(order):
                w = item['parts'][agent] * scale
                gap = 2 if n < len(order) - 1 else 0  # 2px surface gap between segments.
                marks.append(bar(x, y, w - gap, bar_h, AGENT[agent], n == len(order) - 1))
                if w > 34:
                    marks.append(f'<text x="{x + (w - gap) / 2:.1f}" y="{y + bar_h / 2 + 4}" class="seg" '
                                 f'text-anchor="middle">{item["parts"][agent]:.0f}</text>')
                x += w
            lo, hi, mid = left + item['low'] * scale, left + item['high'] * scale, y + bar_h / 2
            marks.append(f'<path d="M{lo:.1f},{mid - 5} v10 M{lo:.1f},{mid} H{hi:.1f} M{hi:.1f},{mid - 5} v10" '
                         f'stroke="{INK}" stroke-width="1.5" fill="none"/>')
            marks.append(f'<text x="{max(hi, x) + 8:.1f}" y="{mid + 4}" class="total">{item["mean"]:.0f} s</text>')
            y += row
        bottom = y - row + bar_h
        grid = []  # Drawn first, so it stays behind the bars.
        for tick in range(0, LIMIT + 1, 100):
            tx = left + tick * scale
            grid.append(f'<line x1="{tx:.1f}" y1="{top - 6}" x2="{tx:.1f}" y2="{bottom + 6}" stroke="{GRID}"/>'
                        f'<text x="{tx:.1f}" y="{bottom + 22}" class="tick" text-anchor="middle">{tick}</text>')
        limit_x = left + LIMIT * scale
        grid.append(f'<line x1="{limit_x:.1f}" y1="{top - 10}" x2="{limit_x:.1f}" y2="{bottom + 6}" stroke="{INK_2}" '
                    f'stroke-width="1.5" stroke-dasharray="5 4"/>'
                    f'<text x="{limit_x:.1f}" y="{top - 14}" class="tick" text-anchor="middle">NFR06 limit (600 s)</text>')
        body += grid + marks
        y = bottom + 50
    height = y + 26  # The last panel's tick labels end about 30 px above y.
    body.append(f'<text x="{left + LIMIT * scale / 2:.1f}" y="{y - 6}" class="tick" text-anchor="middle">'
                'Seconds (bar: mean of the runs; whisker: fastest to slowest run)</text>')
    body.append(f'<text x="16" y="{height - 10}" class="note">{escape(source)}</text>')
    return _svg(width, height, 'Time per phase against the ten-minute limit',
                f'Real Qwen3-8B on the development laptop, simulated server, {runs} runs per scenario. '
                'Segments: time spent in each agent.', ''.join(body))


def _svg(width, height, title, subtitle, body):
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"
 font-family="Segoe UI, system-ui, sans-serif">
<style>
.title {{ font-size: 19px; font-weight: 600; fill: {INK}; }} .subtitle {{ font-size: 13px; fill: {INK_2}; }}
.panel {{ font-size: 14px; font-weight: 600; fill: {INK}; }} .label {{ font-size: 13px; fill: {INK}; }}
.legend {{ font-size: 12.5px; fill: {INK}; }} .tick {{ font-size: 12px; fill: {INK_2}; }}
.total {{ font-size: 12.5px; font-weight: 600; fill: {INK}; }} .seg {{ font-size: 11.5px; font-weight: 600; fill: #ffffff; }}
.note {{ font-size: 11px; fill: {MUTED}; }}
</style>
<rect width="{width}" height="{height}" fill="{SURFACE}"/>
<text x="16" y="32" class="title">{escape(title)}</text>
<text x="16" y="54" class="subtitle">{escape(subtitle)}</text>
{body}
</svg>
'''


def render_png(svg_path, width, height):
    browser = next((p for p in (shutil.which('msedge'), r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
                                r'C:\Program Files\Google\Chrome\Application\chrome.exe') if p and Path(p).exists()), None)
    if browser is None:
        print('No Edge or Chrome found; SVG only:', svg_path)
        return
    page = Path(tempfile.mkdtemp()) / 'figure.html'
    page.write_text(f'<html><body style="margin:0">{svg_path.read_text(encoding="utf-8")}</body></html>', encoding='utf-8')
    png = svg_path.with_suffix('.png')
    subprocess.run([browser, '--headless=new', '--disable-gpu', '--hide-scrollbars', f'--screenshot={png}',
                    f'--window-size={width},{height}', '--force-device-scale-factor=3', page.as_uri()],
                   check=True, capture_output=True, timeout=60)
    print('Wrote', png)


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else EVALUATIONS / '20261027_144751'
    rows = [json.loads(line) for line in (folder / 'results.jsonl').read_text(encoding='utf-8').splitlines() if line]
    runs = max(r['repetition'] for r in rows)
    OUT.mkdir(parents=True, exist_ok=True)
    svg = phase_figure(phase_times(rows), runs, f'Source: data/agentic_evaluations/{folder.name}/results.jsonl')
    path = OUT / 'fig_phase_times.svg'
    path.write_text(svg, encoding='utf-8')
    width, height = (int(v) for v in svg.split('viewBox="0 0 ')[1].split('"')[0].split())
    print('Wrote', path)
    render_png(path, width, height)


if __name__ == '__main__':
    main()
