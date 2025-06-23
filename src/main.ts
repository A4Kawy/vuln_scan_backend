import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for a specific frontend URL
  app.enableCors({
    origin: 'http://localhost:5173', // السماح فقط للفرونت إند بالوصول
    credentials: true, // إذا كنت تستخدم الكوكيز أو التوكن في الهيدر
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: 'Content-Type, Authorization',
  });

  // Apply global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,  // Reject request with unexpected properties
    }),
  );

  // Listen on the specified port, defaulting to 3000
  await app.listen(process.env.PORT ?? 3000);
}

// Start the application
// eslint-disable-next-line @typescript-eslint/no-floating-promises
bootstrap();



