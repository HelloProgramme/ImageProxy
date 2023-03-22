import { Hono } from "hono";
// import axios from 'axios';
// import { fetch } from 'fetch';

const app = new Hono();

app.get("/", (ctx) => ctx.text("Hello world, this is Hono!!"));

app.get("/user", (c) => {
  const userAgent = c.req.header("User-Agent");
  const query = c.req.query();
  // console.log('param :>> ', param);
  console.log("userAgent :>> ", userAgent);
  // const name = c.req.param('name')
  // console.log('name :>> ', name);
  return c.text(JSON.stringify(query, null, "  "));
});

app.get("/proxy", async (c) => {
  const query = c.req.query();
  const { url = undefined } = query;
  if (url === undefined) {
    c.json({ msg: '参数错误' })
  }
  else {
    try {
      const requestOptions = {
        method: "GET",
        headers: {
          "User-Agent":
            " Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        },
        redirect: "follow",
        referrerPolicy: "no-referrer",
      };
      const response = await fetch(url, requestOptions);
      return response;
    } catch (error) {
      c.json({ msg: "图片地址错误" })
    }

  }

});

export default app;
