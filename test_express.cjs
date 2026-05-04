const express = require('express');
const app = express();
try {
  app.options(express.json());
  console.log('SUCCESS: no path');
} catch (e) {
  console.log('FAIL:', e.message);
}
