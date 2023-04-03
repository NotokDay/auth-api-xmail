const app = require('./app');
const { logger } = require('./utils/logger');

const PORT = 443;

app.listen(PORT, () => {
    logger.info(`Running on PORT ${PORT}`);
});
