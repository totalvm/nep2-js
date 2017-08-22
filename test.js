var nep = require('./index.js')
var wif = require('wif')

var priv = 'L2sdgdDpqN97c16C5DNf3FcRNrvYSmo5CNxSSfj5Jfqe9sqVZin2'
var decode = wif.decode(priv)

// console.log(nep.getAddress(decode))
console.log(decode)
console.log(nep.getAddress(decode))
