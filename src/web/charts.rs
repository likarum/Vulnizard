//! Server-rendered SVG charts (no JavaScript).
//!
//! Colors are CSS classes (`fill-*` / `stroke-*`) defined in the stylesheet,
//! so the light and dark themes are selected in one place and no inline
//! style is needed (the Content-Security-Policy forbids it). Every value shown
//! in a chart is also printed in its legend or in a table next to it; the
//! `<title>` elements only add a native tooltip.

use maud::{html, Markup};

use crate::db::DayStats;

/// Categorical slots available for projects; further projects fold into "Other"
pub const PROJECT_SLOTS: usize = 7;

/// Color key of a project slot (the 8th class is the neutral "Other")
pub fn project_color(slot: usize) -> String {
    if slot < PROJECT_SLOTS {
        format!("p{slot}")
    } else {
        "other".to_string()
    }
}

pub const SEVERITIES: [(&str, &str, &str); 5] = [
    ("critical", "Critical", "sev-critical"),
    ("high", "High", "sev-high"),
    ("medium", "Medium", "sev-medium"),
    ("low", "Low", "sev-low"),
    ("none", "No score", "sev-none"),
];

pub const STATUSES: [(&str, &str, &str); 4] = [
    ("untreated", "To review", "st-open"),
    ("accepted", "Risk accepted", "st-accepted"),
    ("treated", "Closed", "st-closed"),
    ("not_applicable", "Not applicable", "st-na"),
];

pub fn status_label(status: &str) -> &'static str {
    STATUSES
        .iter()
        .find(|(key, _, _)| *key == status)
        .map(|(_, label, _)| *label)
        .unwrap_or("Unknown")
}

pub fn status_color(status: &str) -> &'static str {
    STATUSES
        .iter()
        .find(|(key, _, _)| *key == status)
        .map(|(_, _, color)| *color)
        .unwrap_or("st-na")
}

/// One part of a whole
#[derive(Clone)]
pub struct Segment {
    pub label: String,
    pub value: i64,
    /// Color key: the classes `fill-<color>` and `stroke-<color>` exist in the stylesheet
    pub color: String,
}

impl Segment {
    pub fn new(label: impl Into<String>, value: i64, color: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value,
            color: color.into(),
        }
    }
}

fn swatch(color: &str) -> Markup {
    html! {
        svg.swatch width="10" height="10" viewBox="0 0 10 10" aria-hidden="true" {
            rect width="10" height="10" rx="2" class={ "fill-" (color) } {}
        }
    }
}

/// Legend listing every segment with its value (identity is never color alone)
pub fn legend(segments: &[Segment], with_values: bool) -> Markup {
    html! {
        ul.legend {
            @for s in segments {
                li {
                    (swatch(&s.color)) " " (s.label)
                    @if with_values { " " strong { (s.value) } }
                }
            }
        }
    }
}

/// Donut: parts of a whole, total in the centre
pub fn donut(segments: &[Segment], total_label: &str) -> Markup {
    const R: f64 = 54.0;
    const GAP: f64 = 2.0;
    let total: i64 = segments.iter().map(|s| s.value).sum();
    let circumference = 2.0 * std::f64::consts::PI * R;
    let visible: Vec<&Segment> = segments.iter().filter(|s| s.value > 0).collect();
    let mut offset = 0.0;
    html! {
        div.chart.donut {
            svg viewBox="0 0 140 140" width="140" height="140" role="img"
                aria-label={ (total_label) ": " (total) } {
                @if total == 0 {
                    circle cx="70" cy="70" r=(R) class="stroke-track" stroke-width="16" {}
                }
                // Starts at 12 o'clock, clockwise
                g transform="rotate(-90 70 70)" {
                    @for s in &visible {
                        @let share = s.value as f64 / total as f64 * circumference;
                        // 2px surface gap between segments (none for a single one)
                        @let len = if visible.len() > 1 { (share - GAP).max(1.0) } else { share };
                        circle cx="70" cy="70" r=(R) class={ "stroke-" (s.color) } stroke-width="16"
                            stroke-dasharray={ (format!("{len:.2}")) " " (format!("{:.2}", circumference - len)) }
                            stroke-dashoffset=(format!("{:.2}", -offset)) {
                            title { (s.label) ": " (s.value) }
                        }
                        @let _ = { offset += share; };
                    }
                }
                text.total x="70" y="68" text-anchor="middle" { (total) }
                text.caption x="70" y="84" text-anchor="middle" { (total_label) }
            }
            (legend(segments, true))
        }
    }
}

/// Horizontal stacked bars: one row per category, segments sharing one legend
pub fn stacked_rows(rows: &[(String, Vec<Segment>)], legend_segments: &[Segment]) -> Markup {
    const LABEL_W: f64 = 84.0;
    const PLOT_W: f64 = 212.0;
    const ROW_H: f64 = 26.0;
    const BAR_H: f64 = 14.0;
    const GAP: f64 = 2.0;
    let max: i64 = rows
        .iter()
        .map(|(_, segs)| segs.iter().map(|s| s.value).sum::<i64>())
        .max()
        .unwrap_or(0)
        .max(1);
    let height = rows.len() as f64 * ROW_H + 4.0;
    html! {
        div.chart {
            svg viewBox={ "0 0 340 " (height) } width="340" height=(height) role="img" {
                @for (i, (label, segs)) in rows.iter().enumerate() {
                    @let y = i as f64 * ROW_H + 4.0;
                    @let total: i64 = segs.iter().map(|s| s.value).sum();
                    text.label x=(LABEL_W - 8.0) y=(y + 11.0) text-anchor="end" { (label) }
                    rect x=(LABEL_W) y=(y) width=(PLOT_W) height=(BAR_H) rx="4" class="fill-track" {}
                    @let mut x = LABEL_W;
                    @for s in segs.iter().filter(|s| s.value > 0) {
                        @let w = s.value as f64 / max as f64 * PLOT_W;
                        rect x=(format!("{x:.1}")) y=(y) width=(format!("{:.1}", (w - GAP).max(1.0))) height=(BAR_H) rx="3"
                            class={ "fill-" (s.color) } {
                            title { (label) " · " (s.label) ": " (s.value) }
                        }
                        @let _ = { x += w; };
                    }
                    text.value x=(LABEL_W + PLOT_W + 8.0) y=(y + 11.0) { (total) }
                }
            }
            @if legend_segments.len() > 1 { (legend(legend_segments, false)) }
        }
    }
}

const CHART_W: f64 = 1100.0;
const PLOT_LEFT: f64 = 36.0;
const PLOT_RIGHT: f64 = 12.0;
const PLOT_W: f64 = CHART_W - PLOT_LEFT - PLOT_RIGHT;

fn nice_max(value: i64) -> i64 {
    let value = value.max(4);
    let magnitude = 10_i64.pow((value as f64).log10().floor() as u32);
    for step in [1, 2, 4, 5, 10] {
        if step * magnitude >= value {
            return step * magnitude;
        }
    }
    10 * magnitude
}

/// Shared frame of the time charts: gridlines, y ticks, first/middle/last
/// label of the x axis (one label per day, or per week)
fn time_frame(labels: &[&str], max: i64, plot_h: f64) -> Markup {
    let shown: Vec<usize> = match labels.len() {
        0 => vec![],
        1 => vec![0],
        n => vec![0, n / 2, n - 1],
    };
    html! {
        @for tick in [0, max / 2, max] {
            @let y = 8.0 + plot_h - tick as f64 / max as f64 * plot_h;
            line.grid x1=(PLOT_LEFT) x2=(CHART_W - PLOT_RIGHT) y1=(y) y2=(y) {}
            text.label x=(PLOT_LEFT - 6.0) y=(y + 4.0) text-anchor="end" { (tick) }
        }
        @for i in shown {
            @let x = PLOT_LEFT + (i as f64 + 0.5) * PLOT_W / labels.len() as f64;
            text.label x=(x) y=(plot_h + 26.0)
                text-anchor=(if i == 0 { "start" } else if i == labels.len() - 1 { "end" } else { "middle" }) {
                (labels[i])
            }
        }
    }
}

/// Transparent columns, one per label: tooltip, marker of the selected one,
/// and a link to that day when the chart leads somewhere
fn targets(
    labels: &[&str],
    plot_h: f64,
    selected: Option<&str>,
    link: Option<&dyn Fn(&str) -> String>,
    describe: &dyn Fn(usize) -> String,
) -> Markup {
    let col = PLOT_W / labels.len().max(1) as f64;
    html! {
        @for (i, label) in labels.iter().enumerate() {
            @let x = PLOT_LEFT + i as f64 * col;
            @let hit = html! {
                rect.hit x=(format!("{x:.1}")) y="8" width=(format!("{col:.1}")) height=(plot_h) {
                    title { (label) " — " (describe(i)) }
                }
            };
            @if selected == Some(*label) {
                rect.selected x=(format!("{x:.1}")) y="8" width=(format!("{col:.1}")) height=(plot_h) {}
            }
            @if let Some(link) = link { a href=(link(label)) { (hit) } } @else { (hit) }
        }
    }
}

fn day_labels(days: &[DayStats]) -> Vec<&str> {
    days.iter().map(|d| d.day.as_str()).collect()
}

/// Width of a mark in a column: thin, with a gap between neighbours when there is room
fn mark_width(col: f64) -> f64 {
    (col - 2.0).clamp(1.0, 18.0)
}

/// Marks stacked from the baseline up in one column: (value, color key) from the bottom
fn stack(x: f64, width: f64, plot_h: f64, max: i64, parts: &[(i64, &str)]) -> Markup {
    let mut y = 8.0 + plot_h;
    html! {
        @for (value, color) in parts {
            @if *value > 0 {
                @let h = *value as f64 / max as f64 * plot_h;
                @let _ = { y -= h; };
                rect x=(format!("{x:.1}")) y=(format!("{y:.1}")) width=(format!("{width:.1}"))
                    height=(format!("{:.1}", (h - 1.0).max(1.0))) rx="1.5" class={ "fill-" (color) } {}
            }
        }
    }
}

/// Entries to review at the end of each day, stacked by severity (the most
/// severe at the bottom, where its trend reads against the baseline). The
/// severity is the one the CVE has today.
pub fn severity_chart(days: &[DayStats], selected: Option<&str>, link: &dyn Fn(&str) -> String) -> Markup {
    const PLOT_H: f64 = 150.0;
    let max = nice_max(days.iter().map(|d| d.open).max().unwrap_or(0));
    let col = PLOT_W / days.len().max(1) as f64;
    let width = mark_width(col);
    let labels = day_labels(days);
    let last = days.last().map(|d| d.open_by_severity).unwrap_or_default();
    let legend_segments: Vec<Segment> =
        SEVERITIES.iter().zip(last).map(|((_, label, color), value)| Segment::new(*label, value, *color)).collect();
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (PLOT_H + 34.0) } role="img"
                aria-label="CVEs to review per day, by severity" {
                (time_frame(&labels, max, PLOT_H))
                @for (i, d) in days.iter().enumerate() {
                    @let parts: Vec<(i64, &str)> = d.open_by_severity.iter().zip(SEVERITIES).map(|(n, (_, _, color))| (*n, color)).collect();
                    (stack(PLOT_LEFT + i as f64 * col + (col - width) / 2.0, width, PLOT_H, max, &parts))
                }
                (targets(&labels, PLOT_H, selected, Some(link), &|i| {
                    let [critical, high, medium, low, none] = days[i].open_by_severity;
                    format!("{} to review: {critical} critical, {high} high, {medium} medium, {low} low, {none} without a score", days[i].open)
                }))
            }
            (legend(&legend_segments, true))
        }
    }
}

/// One count per day, as a line: `(day, value)` oldest first. `what` names
/// the count ("accepted risks"). A single series: its name is the title of
/// the chart, so there is no legend.
pub fn line_chart(
    points: &[(String, i64)],
    color: &str,
    what: &str,
    plot_h: f64,
    selected: Option<&str>,
    link: &dyn Fn(&str) -> String,
) -> Markup {
    let max = nice_max(points.iter().map(|(_, value)| *value).max().unwrap_or(0));
    let col = PLOT_W / points.len().max(1) as f64;
    let labels: Vec<&str> = points.iter().map(|(day, _)| day.as_str()).collect();
    let line = points
        .iter()
        .enumerate()
        .map(|(i, (_, value))| {
            format!("{:.1},{:.1}", PLOT_LEFT + (i as f64 + 0.5) * col, 8.0 + plot_h - *value as f64 / max as f64 * plot_h)
        })
        .collect::<Vec<_>>()
        .join(" ");
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (plot_h + 34.0) } role="img" aria-label={ (what) " per day" } {
                (time_frame(&labels, max, plot_h))
                polyline class={ "series stroke-" (color) } points=(line) {}
                (targets(&labels, plot_h, selected, Some(link), &|i| format!("{} {what}", points[i].1)))
            }
        }
    }
}

/// Two counts per bucket, side by side: `(label, first, second)` oldest
/// first, and the (name, color key) of each of the two series
pub fn paired_bars(buckets: &[(String, i64, i64)], first: (&str, &str), second: (&str, &str), what: &str) -> Markup {
    const PLOT_H: f64 = 120.0;
    let max = nice_max(buckets.iter().map(|(_, a, b)| *a.max(b)).max().unwrap_or(0));
    let col = PLOT_W / buckets.len().max(1) as f64;
    // Two thin marks and a gap, centred in the column of the bucket
    let width = ((col - 4.0) / 2.0).clamp(1.0, 12.0);
    let labels: Vec<&str> = buckets.iter().map(|(label, _, _)| label.as_str()).collect();
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (PLOT_H + 34.0) } role="img" aria-label=(what) {
                (time_frame(&labels, max, PLOT_H))
                @for (i, (_, a, b)) in buckets.iter().enumerate() {
                    @let x = PLOT_LEFT + i as f64 * col + col / 2.0;
                    (stack(x - width - 0.5, width, PLOT_H, max, &[(*a, first.1)]))
                    (stack(x + 0.5, width, PLOT_H, max, &[(*b, second.1)]))
                }
                (targets(&labels, PLOT_H, None, None, &|i| format!("{} {}, {} {}", buckets[i].1, first.0, buckets[i].2, second.0)))
            }
            (legend(&[
                Segment::new(first.0, buckets.iter().map(|(_, a, _)| a).sum(), first.1),
                Segment::new(second.0, buckets.iter().map(|(_, _, b)| b).sum(), second.1),
            ], true))
        }
    }
}

/// Daily activity: new entries and decisions, stacked per day
pub fn activity_chart(days: &[DayStats], selected: Option<&str>, link: &dyn Fn(&str) -> String) -> Markup {
    const PLOT_H: f64 = 120.0;
    let parts = |d: &DayStats| {
        [
            (d.new + d.reopened, "st-open"),
            (d.accepted, "st-accepted"),
            (d.closed, "st-closed"),
            (d.not_applicable, "st-na"),
        ]
    };
    let max = nice_max(
        days.iter()
            .map(|d| parts(d).iter().map(|(v, _)| v).sum::<i64>())
            .max()
            .unwrap_or(0),
    );
    let col = PLOT_W / days.len().max(1) as f64;
    let width = mark_width(col);
    let labels = day_labels(days);
    let sum = |f: &dyn Fn(&DayStats) -> i64| days.iter().map(f).sum::<i64>();
    html! {
        div.chart {
            svg viewBox={ "0 0 " (CHART_W) " " (PLOT_H + 34.0) } role="img"
                aria-label="New entries and decisions per day" {
                (time_frame(&labels, max, PLOT_H))
                @for (i, d) in days.iter().enumerate() {
                    (stack(PLOT_LEFT + i as f64 * col + (col - width) / 2.0, width, PLOT_H, max, &parts(d)))
                }
                (targets(&labels, PLOT_H, selected, Some(link), &|i| format!(
                    "{} new, {} accepted, {} closed, {} not applicable",
                    days[i].new + days[i].reopened, days[i].accepted, days[i].closed, days[i].not_applicable
                )))
            }
            (legend(&[
                Segment::new("New or reopened", sum(&|d| d.new + d.reopened), "st-open"),
                Segment::new("Risk accepted", sum(&|d| d.accepted), "st-accepted"),
                Segment::new("Closed", sum(&|d| d.closed), "st-closed"),
                Segment::new("Not applicable", sum(&|d| d.not_applicable), "st-na"),
            ], true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn donut_draws_one_arc_per_non_empty_segment() {
        let svg = donut(
            &[
                Segment::new("io", 3, "p0"),
                Segment::new("pawn", 1, "p1"),
                Segment::new("empty", 0, "p2"),
            ],
            "to review",
        )
        .into_string();
        assert_eq!(svg.matches("<circle").count(), 2);
        assert!(svg.contains("stroke-p0") && svg.contains("stroke-p1") && !svg.contains("stroke-p2"));
        assert!(svg.contains(">4</text>"));
        // Every segment, even empty, is named in the legend
        assert!(svg.contains("empty"));
        // No inline style: the CSP forbids it
        assert!(!svg.contains("style="));
    }

    #[test]
    fn svg_elements_are_explicitly_closed() {
        // In HTML an SVG element is never void: an unclosed <rect> would swallow what follows
        let days = vec![DayStats { day: "2026-01-01".into(), new: 2, open: 2, open_by_severity: [1, 0, 1, 0, 0], ..Default::default() }];
        let link = |d: &str| d.to_string();
        let points = vec![("2026-01-01".to_string(), 2)];
        let weeks = vec![("2026-01-05".to_string(), 2, 1)];
        let rows = vec![("io".to_string(), vec![Segment::new("a", 2, "p0"), Segment::new("b", 1, "p1")])];
        for svg in [
            donut(&[Segment::new("a", 1, "p0"), Segment::new("b", 2, "p1")], "t").into_string(),
            stacked_rows(&rows, &rows[0].1).into_string(),
            severity_chart(&days, Some("2026-01-01"), &link).into_string(),
            line_chart(&points, "st-accepted", "accepted risks", 60.0, None, &link).into_string(),
            paired_bars(&weeks, ("detected", "p0"), ("due", "p1"), "Overdue entries per week").into_string(),
            activity_chart(&days, None, &link).into_string(),
        ] {
            // A repeated attribute is dropped by the browser (the color would be lost)
            assert!(!svg.contains("\" class=\"") || !regex::Regex::new(r#"<[a-z]+ [^>]*class="[^"]*"[^>]*class=""#).unwrap().is_match(&svg));
            for tag in ["rect", "circle", "line", "polyline"] {
                assert_eq!(
                    svg.matches(&format!("<{tag} ")).count(),
                    svg.matches(&format!("</{tag}>")).count(),
                    "unclosed <{tag}>"
                );
            }
        }
    }

    #[test]
    fn empty_donut_shows_a_track_and_zero() {
        let svg = donut(&[Segment::new("io", 0, "p0")], "to review").into_string();
        assert!(svg.contains("stroke-track"));
        assert!(svg.contains(">0</text>"));
    }

    #[test]
    fn labels_are_escaped() {
        let svg = donut(&[Segment::new("<script>x</script>", 1, "p0")], "t").into_string();
        assert!(!svg.contains("<script>"));
    }

    #[test]
    fn time_charts_link_every_day_and_scale_nicely() {
        let days: Vec<DayStats> = (1..=3)
            .map(|i| DayStats {
                day: format!("2026-01-0{i}"),
                new: i,
                open: i * 3,
                accepted_total: i,
                // No high one on the first day
                open_by_severity: [i, i - 1, i, 0, 1],
                ..Default::default()
            })
            .collect();
        let link = |day: &str| format!("/product?view=history&at={day}");
        let stock = severity_chart(&days, Some("2026-01-02"), &link).into_string();
        assert_eq!(stock.matches("<a href=").count(), 3);
        assert_eq!(stock.matches("class=\"selected\"").count(), 1);
        assert!(stock.contains("at=2026-01-03"));
        // One mark per day and per severity that has entries, plus the legend; the legend gives the last day
        for (color, marks) in [("sev-critical", 3), ("sev-high", 2), ("sev-medium", 3), ("sev-low", 0), ("sev-none", 3)] {
            assert_eq!(stock.matches(&format!("fill-{color}")).count(), marks + 1, "{color}");
        }
        assert!(stock.contains("Critical <strong>3</strong>") && stock.contains("High <strong>2</strong>") && stock.contains("No score <strong>1</strong>"));
        // The figures of a day are in its tooltip, in words
        assert!(stock.contains("<title>2026-01-02 — 6 to review: 2 critical, 1 high, 2 medium, 0 low, 1 without a score</title>"), "{stock}");
        // The text of a chart takes its color from the page, never from a series
        assert!(!regex::Regex::new(r#"<text[^>]*(fill-|stroke-)"#).unwrap().is_match(&stock));
        let activity = activity_chart(&days, None, &link).into_string();
        assert_eq!(activity.matches("fill-st-open").count(), 3 + 1); // three bars + legend
        assert_eq!((nice_max(0), nice_max(9), nice_max(37), nice_max(120)), (4, 10, 40, 200));
        assert!(severity_chart(&[], None, &link).into_string().contains("<svg"));

        // A single series is a line without a legend: its title names it
        let points: Vec<(String, i64)> = days.iter().map(|d| (d.day.clone(), d.accepted_total)).collect();
        let line = line_chart(&points, "st-accepted", "accepted risks", 60.0, Some("2026-01-03"), &link).into_string();
        assert_eq!((line.matches("<polyline").count(), line.matches("<a href=").count(), line.matches("class=\"legend\"").count()), (1, 3, 0));
        assert!(line.contains("stroke-st-accepted") && line.contains("<title>2026-01-03 — 3 accepted risks</title>"));
        assert!(line_chart(&[], "p0", "overdue", 60.0, None, &link).into_string().contains("<svg"));

        // Two series side by side: a legend with their totals, and no link (a week is not a day)
        let weeks = vec![("2026-01-05".to_string(), 4, 0), ("2026-01-12".to_string(), 1, 5)];
        let pairs = paired_bars(&weeks, ("detected", "p0"), ("due", "p1"), "Overdue entries per week").into_string();
        assert_eq!((pairs.matches("fill-p0").count(), pairs.matches("fill-p1").count(), pairs.matches("<a href=").count()), (2 + 1, 1 + 1, 0));
        assert!(pairs.contains("detected <strong>5</strong>") && pairs.contains("due <strong>5</strong>"));
        assert!(pairs.contains("<title>2026-01-12 — 1 detected, 5 due</title>"));
        assert!(paired_bars(&[], ("a", "p0"), ("b", "p1"), "x").into_string().contains("<svg"));
    }

    #[test]
    fn projects_beyond_the_palette_fold_into_other() {
        assert_eq!(project_color(0), "p0");
        assert_eq!(project_color(PROJECT_SLOTS - 1), "p6");
        assert_eq!(project_color(PROJECT_SLOTS), "other");
        assert_eq!(project_color(40), "other");
    }
}
