import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // Use SSL/TLS
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false,
    },
});

export const sendEmail = async (to, subject, setPasswordLink) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to,
            subject,
            html: `
                <!DOCTYPE html>
                <html>
                  <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>You're Invited!</title>
                    <style>
                      body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f4;
                      }
                      .container {
                        max-width: 600px;
                        margin: 40px auto;
                        background: #ffffff;
                        padding: 20px;
                        border-radius: 10px;
                        text-align: center;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                      }
                      h2 {
                        color: #333;
                      }
                      p {
                        color: #555;
                        font-size: 16px;
                        line-height: 1.5;
                      }
                      .btn {
                        display: inline-block;
                        padding: 12px 20px;
                        font-size: 16px;
                        color: #fff;
                        background: #007bff;
                        text-decoration: none;
                        border-radius: 5px;
                        font-weight: bold;
                        margin-top: 20px;
                      }
                      .footer {
                        margin-top: 20px;
                        font-size: 14px;
                        color: #777;
                      }
                    </style>
                  </head>
                  <body>
                    <div class="container">
                      <h2>You're Invited to Join Our Company!</h2>
                      <p>We’re excited to have you on board. Click the button below to set up your account password and join us.</p>
                      <a href="${setPasswordLink}" class="btn">Set Your Password</a>
                      <p class="footer">If you did not request this invitation, please ignore this email.</p>
                    </div>
                  </body>
                </html>
            `,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log("Email sent:", info.response);
    } catch (error) {
        console.error("Error sending email:", error.message);
    }
};
