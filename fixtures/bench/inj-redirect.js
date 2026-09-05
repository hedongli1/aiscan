const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  const url = req.query.next;
  res.redirect(url); // L6 命中重定向
});

app.post('/login', (req, res) => {
  res.redirect(`/home?token=${req.body.redirect}`); // L11 命中模板重定向
});

app.get('/safe', (req, res) => {
  res.redirect('/dashboard'); // L15 不命中（固定路径）
});
