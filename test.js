const selectclientcert = require('bindings')('selectclientcert');

const result = selectclientcert.selectClientCert([]);
console.log(result);