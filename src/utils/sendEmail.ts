import nodemailer from "nodemailer";

export const sendEmail = async ({
  to,
  subject,
  text,
  html,
}: {
  to: string;
  subject: string;
  text: string;
  html?: string;
}) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, 
    auth: {
      user: "yashpawar12122004@gmail.com", 
      pass: "arhj ynqn zxbk dncj", 
    },
  });

  await transporter.sendMail({
    from: "yashpawar12122004@gmail.com", 
    to,
    subject,
    text,
    html,
  });
};
