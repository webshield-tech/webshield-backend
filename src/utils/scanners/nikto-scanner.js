import { spawn } from 'child_process';

export async function scanWithNikto(targetUrl) {
  try {
    console.log('Starting Nikto Scan for:  ', targetUrl);

    // Extract hostname and port
    let hostname = targetUrl;
    let port = 80;
    let useSsl = false;
    try {
      const urlObj = new URL(targetUrl);
      hostname = urlObj.hostname;
      port = Number(urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80));
      useSsl = urlObj.protocol === 'https:';
      console.log('Extracted hostname:', hostname);
    } catch (err) {
      console.log('Using original target as hostname:', hostname);
    }

    console.log('start scanning nikto for', hostname);

    // Build args array (no shell interpolation - prevents command injection)
    const args = ['-h', hostname, '-port', String(port)];
    if (useSsl) args.push('-ssl');
    args.push('-Tuning', 'b', '-maxtime', '120s', '-nointeractive');

    console.log('Running Nikto with args:', args.join(' '));

    const { stdout } = await new Promise((resolve, reject) => {
      const proc = spawn('nikto', args, { timeout: 180000 });
      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d) => (stdout += d));
      proc.stderr.on('data', (d) => (stderr += d));
      proc.on('close', (code) => {
        if (code === 0 || stdout.length > 0) resolve({ stdout, stderr });
        else reject(new Error(stderr || `Nikto exited with code ${code}`));
      });
      proc.on('error', reject);
    });

    console.log('Nikto scan completed.  Output length:', stdout.length);

    // Parse Nikto output
    const findings = [];
    const lines = stdout.split('\n');

    lines.forEach(line => {
      // Look for findings (lines starting with + that aren't metadata)
      if (
        line.startsWith('+ ') &&
        !line.includes('Target IP:') &&
        !line.includes('Target Hostname:') &&
        !line.includes('Target Port:') &&
        !line.includes('Start Time:') &&
        !line.includes('End Time:') &&
        !line.includes('Server:') &&
        !line.includes('requests:') &&
        !line.includes('item(s) reported') &&
        !line.includes('host(s) tested') &&
        line.length > 10
      ) {
        const cleanedLine = line.substring(2).trim();
        if (cleanedLine && !findings.includes(cleanedLine)) {
          findings.push(cleanedLine);
        }
      }
    });

    console.log(`Nikto scan found ${findings.length} findings`);

    return {
      tool: 'nikto',
      success: true,
      totalFindings: findings.length,
      findings: findings.slice(0, 50), 
      rawOutput: stdout.substring(0, 5000), 
      target: hostname,
    };
  } catch (error) {
    console.error('Nikto scan error:', error.message);

    if (error.killed) {
      return {
        tool: 'nikto',
        success: false,
        error: 'Scan timed out after 3 minutes',
        totalFindings: 0,
        findings: [],
        rawOutput: error.stdout || 'Scan timed out',
        target: targetUrl,
      };
    }

    return {
      tool: 'nikto',
      success: false,
      error: error.message,
      totalFindings: 0,
      findings: [],
      rawOutput: error.stdout || error.stderr || 'No output',
      target: targetUrl,
    };
  }
}