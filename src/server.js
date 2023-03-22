import { Hono } from "hono";
const app = new Hono();

app.get("/", (ctx) => ctx.text("Hello world, this is Hono!!"));

app.get('/user', (c) => {
  const userAgent = c.req.header('User-Agent');
  const query = c.req.query();
  // console.log('param :>> ', param);
  console.log('userAgent :>> ', userAgent);
  // const name = c.req.param('name')
  // console.log('name :>> ', name);
  return c.text(JSON.stringify(query, null, '  '));
})


export default app;