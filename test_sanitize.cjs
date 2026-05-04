const mongoSanitize = require('express-mongo-sanitize');
const obj = { "$where": "sleep(10)" };
mongoSanitize.sanitize(obj);
console.log(obj);
