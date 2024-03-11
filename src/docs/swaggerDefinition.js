const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Chattie API Documentation',
    version: '1.0.0',
    description: 'API documentation for the Chattie application',
  },
  servers: [
    {
      url: 'http://localhost:3200',
    },
  ],
};

module.exports = swaggerDefinition;
