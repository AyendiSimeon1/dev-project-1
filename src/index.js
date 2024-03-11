const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./docs/swaggerSpec');
const app = require('./routes/userRoutes');

// Serve Swagger UI at /api-docs route
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const port = process.env.PORT || 3200;
app.listen(port, () => console.log(`listening at http://localhost:${port}`));
