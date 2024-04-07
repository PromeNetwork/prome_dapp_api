import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { tap } from 'rxjs/internal/operators/tap';

@Injectable()
export default class RepeatSubmitInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): any {
    console.log('Before...');
    const now = Date.now();
    console.log(now);
    return next
      .handle()
      .pipe(tap(() => console.log(`After... ${Date.now() - now}ms`)));
  }
}
