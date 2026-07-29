import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import authRoutes from './routes/auth.routes';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://accounts.google.com"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://oauth2.googleapis.com", "https://www.googleapis.com"],
      frameSrc: ["'self'", "https://accounts.google.com"],
    }
  }
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

app.use('/auth', authRoutes);

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`Identity system running on port ${PORT}`));

// Prevent unhandled promise rejections (thrown by async Express 4 handlers) from crashing the process
process.on('unhandledRejection', (reason: any) => {
  console.error('⚠️ Unhandled Promise Rejection:', reason?.message || reason);
});

process.on('uncaughtException', (err: any) => {
  console.error('⚠️ Uncaught Exception:', err?.message || err);
});