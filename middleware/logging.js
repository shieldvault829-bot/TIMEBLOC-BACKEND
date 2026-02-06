// backend/middleware/logging.js
const morgan = require('morgan');

const logging = morgan(':method :url :status :response-time ms - :res[content-length]');

module.exports = logging;