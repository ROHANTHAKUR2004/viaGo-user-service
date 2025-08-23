import { config } from 'dotenv';
import express from 'express';
config()
const app = express();
const PORT =  process.env.PORT ?? 5000
app.listen(PORT , ()=>{
    console.log(`user service is running on port : ${PORT}`)
})
