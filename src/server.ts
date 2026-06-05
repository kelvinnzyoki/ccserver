import { app } from './app.js';
import { env } from './config/env.js';
app.listen(env.PORT, () => console.log(`Classic Closet API running on :${env.PORT}`));
