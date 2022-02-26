/*
const { exec } = require('child_process');
//'ls -lh' list files in directory
exec('./opera-proxy', (error, stdout, stderr) => {
  if (error) {
    console.error(`error: ${error.message}`);
    return;
  }

  if (stderr) {
    console.error(`stderr: ${stderr}`);
    return;
  }

  console.log(`stdout:\n${stdout}`);
});
*/

//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

var http = require("http")

var port = process.env.PORT || 5000

var server = http.createServer()

server.on('request', (req, res) => {
    res.on('error', (err) => {
      console.error(err);
    });

    if (req.url == '/now') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write(JSON.stringify({ now: new Date() }));
        res.end();
    } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.write('example page\n');
        res.end('Hello World\n');
    }
});

server.listen(port)
