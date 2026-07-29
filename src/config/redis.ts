import Redis from 'ioredis';
import { env } from './env';

class MemoryRedis {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  async get(key: string): Promise<string | null> {
    const item = this.store.get(key);
    if (!item) return null;
    if (item.expiresAt && item.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  async set(key: string, value: string, mode?: string, duration?: number): Promise<'OK'> {
    let expiresAt: number | undefined;
    if (mode === 'EX' && duration) {
      expiresAt = Date.now() + duration * 1000;
    } else if (mode === 'PX' && duration) {
      expiresAt = Date.now() + duration;
    }
    this.store.set(key, { value, expiresAt });
    return 'OK';
  }

  async incr(key: string): Promise<number> {
    const val = await this.get(key);
    const num = val ? parseInt(val, 10) + 1 : 1;
    await this.set(key, num.toString());
    return num;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const item = this.store.get(key);
    if (!item) return 0;
    item.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  async ttl(key: string): Promise<number> {
    const item = this.store.get(key);
    if (!item) return -2;
    if (item.expiresAt) {
      const remaining = Math.round((item.expiresAt - Date.now()) / 1000);
      return remaining > 0 ? remaining : -2;
    }
    return -1;
  }

  async del(key: string): Promise<number> {
    return this.store.delete(key) ? 1 : 0;
  }

  pipeline() {
    const commands: (() => Promise<any>)[] = [];
    const self = this;
    const api = {
      incr(key: string) {
        commands.push(() => self.incr(key));
        return api;
      },
      expire(key: string, seconds: number) {
        commands.push(() => self.expire(key, seconds));
        return api;
      },
      async exec() {
        const results = [];
        for (const cmd of commands) {
          try {
            results.push([null, await cmd()]);
          } catch (err) {
            results.push([err, null]);
          }
        }
        return results;
      }
    };
    return api;
  }
}

let activeClient: any;
let isFallback = false;

const memoryClient = new MemoryRedis();

try {
  const client = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    retryStrategy() {
      return null; // Do not retry
    }
  });

  client.on('error', (err) => {
    if (!isFallback) {
      console.warn('⚠️ Redis connection failed. Falling back to In-Memory rate limiter.', err.message);
      isFallback = true;
      activeClient = memoryClient;
    }
  });

  activeClient = client;
} catch (err) {
  console.warn('⚠️ Failed to initialize Redis client. Using In-Memory store instead.');
  activeClient = memoryClient;
  isFallback = true;
}

export const redis = new Proxy({} as any, {
  get(target, prop) {
    if (isFallback) {
      return (memoryClient as any)[prop];
    }
    if (activeClient && activeClient.status !== 'ready' && activeClient.status !== 'connecting') {
      isFallback = true;
      activeClient = memoryClient;
      return (memoryClient as any)[prop];
    }
    return activeClient[prop];
  }
});
