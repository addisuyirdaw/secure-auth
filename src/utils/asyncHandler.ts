import { Request, Response, NextFunction } from 'express';

type AsyncHandler = (req: Request, res: Response, next: NextFunction) => Promise<any>;

/**
 * Wraps an async Express route handler so that any thrown error is forwarded
 * to Express's next(err) error handler instead of becoming an unhandled rejection.
 * Required for Express 4 which does NOT natively handle async errors.
 */
export function asyncHandler(fn: AsyncHandler) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
