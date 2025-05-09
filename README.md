Install:
1. Docker
2. Docker-Compose
3. ngrok

   Clone repo,
   run docker-compose build app in root,
   then docker-compose up -d,
   check if all three containers are running by docker-compose ps (redis,app,postgre)

   now if you go to localhost port 5000 u can see app but it wont work as this is http, and webauthn requires https, so thats why we will use ngrok.
   ngroks open a secure tunnel to ur 5000 port which can be accessed from anywhere, any device on the internet.

   now open the installed ngrok.exe
   give command ngrok 5000 http
   you will get a url,
   put that url in ur browser
   use app from there.

   limitation:
   in webauthn, all registered users and passkeys are tied to the url,
   we have free version of ngrok in which url changes everytime
   so our device has to register everytime again
