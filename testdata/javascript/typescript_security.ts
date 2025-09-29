// TypeScript security vulnerabilities
import express from 'express';
import { exec, spawn } from 'child_process';
import * as fs from 'fs';
import { Pool } from 'pg';

interface UserRequest {
  id: string;
  name: string;
  command?: string;
}

class TypeScriptVulnerabilities {
  // Command injection in TypeScript
  async executeCommand(req: express.Request, res: express.Response): Promise<void> {
    const userCmd: string = req.body.command;
    exec(`echo ${userCmd}`, (error, stdout, stderr) => {
      res.send(stdout);
    });
  }

  // Code injection with TypeScript
  evaluateExpression(req: express.Request, res: express.Response): void {
    const expr: string = req.query.expression as string;
    const result = eval(expr); // Dangerous eval
    res.json({ result });
  }

  // SQL injection with typed parameters
  async getUserById(req: express.Request, res: express.Response): Promise<void> {
    const userId: string = req.params.id;
    const pool = new Pool();
    
    // Vulnerable query construction
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    const result = await pool.query(query);
    res.json(result.rows);
  }

  // Path traversal with TypeScript
  readUserFile(req: express.Request, res: express.Response): void {
    const filename: string = req.params.filename;
    const filepath = `/user-uploads/${filename}`;
    
    fs.readFile(filepath, 'utf8', (err, data) => {
      if (err) {
        res.status(404).send('File not found');
      } else {
        res.send(data);
      }
    });
  }

  // XSS in template rendering
  renderUserContent(req: express.Request, res: express.Response): void {
    const content: string = req.body.content;
    const html = `<div>${content}</div>`; // Direct interpolation
    res.send(html);
  }

  // Unsafe deserialization
  processUserData(req: express.Request, res: express.Response): void {
    const serializedUser: string = req.body.userData;
    const user: UserRequest = JSON.parse(serializedUser);
    
    // Additional vulnerability with eval
    if (user.command) {
      eval(user.command);
    }
    
    res.json(user);
  }
}

// Modern JavaScript/TypeScript patterns
class ModernVulnerabilities {
  // Async/await command injection
  async processFile(req: express.Request, res: express.Response): Promise<void> {
    const filename: string = req.query.file as string;
    
    try {
      const { stdout } = await execPromise(`file ${filename}`);
      res.send(stdout);
    } catch (error) {
      res.status(500).send('Error processing file');
    }
  }

  // Template literal injection
  buildQuery(req: express.Request, res: express.Response): void {
    const table: string = req.params.table;
    const condition: string = req.query.where as string;
    
    const query = `SELECT * FROM ${table} WHERE ${condition}`;
    // This would be executed with database client
    res.json({ query });
  }

  // Dynamic import vulnerability
  async loadModule(req: express.Request, res: express.Response): Promise<void> {
    const moduleName: string = req.query.module as string;
    
    try {
      const module = await import(moduleName); // Dangerous dynamic import
      res.json(module);
    } catch (error) {
      res.status(500).send('Module not found');
    }
  }
}

// Safe implementations with proper sanitization
class SafeImplementations {
  async safeCommand(req: express.Request, res: express.Response): Promise<void> {
    const userInput: string = req.body.input;
    const sanitized = this.sanitizeCommand(userInput);
    
    exec(`echo ${sanitized}`, (error, stdout, stderr) => {
      res.send(stdout);
    });
  }

  safeSQLQuery(req: express.Request, res: express.Response): void {
    const userId: string = req.params.id;
    const pool = new Pool();
    
    // Parameterized query (safe)
    pool.query('SELECT * FROM users WHERE id = $1', [userId], (err, result) => {
      res.json(result.rows);
    });
  }

  safeFileRead(req: express.Request, res: express.Response): void {
    const filename: string = req.params.filename;
    const sanitizedFilename = this.sanitizeFilename(filename);
    const safePath = `/safe-directory/${sanitizedFilename}`;
    
    fs.readFile(safePath, 'utf8', (err, data) => {
      res.send(data);
    });
  }

  private sanitizeCommand(input: string): string {
    return input.replace(/[^a-zA-Z0-9\s]/g, '');
  }

  private sanitizeFilename(filename: string): string {
    return filename.replace(/[^a-zA-Z0-9.-]/g, '');
  }
}

function execPromise(command: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

export { TypeScriptVulnerabilities, ModernVulnerabilities, SafeImplementations };