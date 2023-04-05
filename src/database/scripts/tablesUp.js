const { logger } = require('../../utils/logger');
const { createTableUSers: createTableUSersQuery } = require('../queries');
const { createTableOTPsQuery } = require('../queries');


(() => {    
   require('../../config/db.config').query(createTableUSersQuery, (err, _) => {
        if (err) {
            logger.error(err.message);
        }
        logger.info('Table users created!');
    });
})();

(() => {    
    require('../../config/db.config').query(createTableOTPsQuery, (err, _) => {
         if (err) {
             logger.error(err.message);
             return;
         }
         logger.info('Table otp created!');
         process.exit(0);
     });
 })();
 
