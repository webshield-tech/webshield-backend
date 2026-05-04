const express = require('express');
const app = express();
const paths = ['/*', '/(.*)', '/:path(.*)', '*'];
for (const p of paths) {
  try {
    app.options(p, (req, res) => {});
    console.log('SUCCESS:', p);
  } catch (e) {
    console.log('FAIL:', p, e.message);
  }
}
