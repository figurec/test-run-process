
const { exec } = require('child_process');
//'ls -lh' list files in directory
exec('./opera/bin/opera-proxy -country EU', (error, stdout, stderr) => {
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

/*
var http = require('http');
http.createServer(function(request, response){

    //The following code will print out the incoming request text
    request.pipe(response);

}).listen(8080, '127.0.0.1');
console.log('Listening on port 8080...');
*/

/*
var net = require('net');
var exp = new net.Socket();
  const addr = { port: 18080 };
  exp.connect(addr, function() {
    console.log('connect');
  });
  exp.on('error', function(ex) {
	  console.log('Ошибка сокета ' + ex);
  });
*/

//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

var WebSocketServer = require("ws").Server
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

console.log("http server listening on %d", port)

var wss = new WebSocketServer({server: server})

var net = require('net');

wss.on("connection", function(ws) {

  //console.log('client');
  var client = new net.Socket();
  var state = new Boolean(false);
  var queue = [];

  const addr = { host: 'localhost', port: 18080 };
  //const addr = { host: 'example.com', port: 80 }; 
  client.connect(addr, function() {
    while(queue.length > 0){
      client.write(queue.pop());
    }
    state = true;
  });

  client.on('error', function(ex) {
	  console.log('Ошибка сокета ' + ex);
  });
  
  client.on('data', function(data) {
    //console.log('send');
    //console.log(data.toString());
    if (ws.readyState == ws.OPEN){
      ws.send(data);
    }
  });
  
  client.on('close', function() {
    ws.close();
    client.destroy(); // kill client after server's response
  });

  //\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  ws.on('message', function incoming(message) {
    //console.log(message.toString());
    if (state === false)
      queue.push(message);
    else
      client.write(message);
  });

  ws.on("close", function() {
    //console.log("close");
    //ws.destroy();
    client.destroy();
  })

  ws.on('error', function(ex){
    console.log('Ошибка вебоокета ' + ex);
  });

})
