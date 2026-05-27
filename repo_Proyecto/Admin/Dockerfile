FROM nginx:1.27-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/app.conf
COPY index.html /usr/share/nginx/html/
COPY admin.css /usr/share/nginx/html/
COPY admin.js /usr/share/nginx/html/
COPY robots.txt /usr/share/nginx/html/
COPY .well-known/ /usr/share/nginx/html/.well-known/
EXPOSE 80
