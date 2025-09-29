// Command injection vulnerabilities
const express = require('express');
const { exec, spawn } = require('child_process');

class VulnerableController {
  // Command injection via exec
  commandInjection1(req, res) {
    const userInput = req.query.cmd;
    exec(`ls ${userInput}`, (error, stdout, stderr) => {
      res.send(stdout);
    });
  }

  // Command injection via spawn
  commandInjection2(req, res) {
    const filename = req.params.file;
    spawn('cat', [filename], (error, stdout, stderr) => {
      res.send(stdout);
    });
  }

  // Code injection vulnerabilities
  codeInjection1(req, res) {
    const userCode = req.body.code;
    eval(userCode); // Dangerous eval
    res.send('Executed');
  }

  codeInjection2(req, res) {
    const expression = req.query.expr;
    const result = Function(expression)(); // Dynamic function creation
    res.json(result);
  }

  // XSS vulnerabilities
  xssVulnerability1(req, res) {
    const message = req.query.message;
    res.send(`<h1>${message}</h1>`); // Direct output without escaping
  }

  xssVulnerability2(req, res) {
    const content = req.body.content;
    res.render('page', { content: content }); // Template injection
  }

  // SQL injection vulnerabilities
  sqlInjection1(req, res) {
    const userId = req.params.id;
    const mysql = require('mysql');
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    mysql.query(query, (error, results) => {
      res.json(results);
    });
  }

  sqlInjection2(req, res) {
    const searchTerm = req.query.search;
    const { Pool } = require('pg');
    const pool = new Pool();
    pool.query(`SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`, (err, result) => {
      res.json(result.rows);
    });
  }

  // Path traversal vulnerabilities
  pathTraversal1(req, res) {
    const filename = req.params.filename;
    const fs = require('fs');
    fs.readFile(`/uploads/${filename}`, 'utf8', (err, data) => {
      res.send(data);
    });
  }

  pathTraversal2(req, res) {
    const filepath = req.query.path;
    const fs = require('fs');
    const content = fs.readFileSync(filepath, 'utf8');
    res.send(content);
  }

  // Unsafe deserialization
  unsafeDeserialization1(req, res) {
    const serializedData = req.body.data;
    const obj = JSON.parse(serializedData); // Could be dangerous with reviver
    res.json(obj);
  }

  unsafeDeserialization2(req, res) {
    const userData = req.body.user;
    eval(`var user = ${userData};`); // Eval-based deserialization
    res.json(user);
  }
}

// Sanitized examples (should not trigger vulnerabilities)
class SafeController {
  safeCommand(req, res) {
    const userInput = req.query.cmd;
    const sanitized = sanitizeInput(userInput);
    exec(`ls ${sanitized}`, (error, stdout, stderr) => {
      res.send(stdout);
    });
  }

  safeXSS(req, res) {
    const message = req.query.message;
    const escaped = escape(message);
    res.send(`<h1>${escaped}</h1>`);
  }
}

function sanitizeInput(input) {
  return input.replace(/[^a-zA-Z0-9]/g, '');
}

function escape(str) {
  return str.replace(/[&<>"']/g, function(match) {
    const escapeMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;'
    };
    return escapeMap[match];
  });
}

module.exports = { VulnerableController, SafeController };