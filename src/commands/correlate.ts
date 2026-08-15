import { cmdFleet } from './fleet.js';
import { computeCorrelation, type CorrelationOptions } from '../correlation/matrix.js';
import { buildReport, formatReportText, formatReportJson } from '../correlation/scoring.js';
import type { PeepConfig, OutputFormat } from '../types.js';
import { c, writeOutputFile } from '../utils.js';

export async function cmdCorrelate(
  domains: string[],
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const format = (flags.format as OutputFormat) || 'text';
  const outFile = flags.out ? String(flags.out) : null;

  // If domains passed as CLI args, use those instead of fleet config
  const effectiveConfig = domains.length > 0
    ? { ...config, fleet: { ...config.fleet, domains } }
    : config;

  // First, scan the entire fleet (show progress in text mode, suppress for JSON)
  const fleetFlags = { ...flags, format: format === 'json' ? 'text' : format };
  const results = await cmdFleet(effectiveConfig, fleetFlags);

  if (format === 'text') {
    console.log(`\n${c('bold', 'Computing cross-site correlation...')}\n`);
  }

  // Compute correlation
  const corrOpts: CorrelationOptions = { verbose: flags.verbose === true };
  const { findings, matrix } = computeCorrelation(results, effectiveConfig.fleet.clusters, corrOpts);
  const report = buildReport(results, findings, matrix);

  if (outFile) {
    // .json → JSON report; any other extension → the human-readable text report
    const content = outFile.endsWith('.json') ? formatReportJson(report) : formatReportText(report);
    const full = writeOutputFile(outFile, content);
    console.error(`\nReport written to ${c('cyan', full)}`); // stderr keeps JSON stdout clean
  }

  if (format === 'json') {
    console.log(formatReportJson(report));
  } else {
    console.log(formatReportText(report));

    if (report.summary.critical > 0) {
      console.log(c('red', `\nExit code 2: ${report.summary.critical} critical findings need immediate attention`));
    } else if (report.score < config.thresholds.correlationWarning) {
      console.log(c('yellow', `\nExit code 1: Isolation score ${report.score}/100 below warning threshold ${config.thresholds.correlationWarning}`));
    } else {
      const down = report.unreachable?.length ?? 0;
      const caveat = down > 0 ? c('yellow', ` (${down} of ${report.domains.length} sites unreachable — content-level correlation not evaluated for them)`) : '';
      console.log(c('green', `\nFleet isolation score: ${report.score}/100 — looks good`) + caveat);
    }
  }

  // Gate outside the format branch: JSON is what CI consumes, so it must exit
  // non-zero too. Previously `-j` always exited 0, silently passing any gate.
  if (report.summary.critical > 0) {
    process.exit(2);
  } else if (report.score < config.thresholds.correlationWarning) {
    process.exit(1);
  }
}
