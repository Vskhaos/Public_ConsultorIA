FROM nginx:1.27-alpine

# Eliminar la config por defecto de nginx
RUN rm /etc/nginx/conf.d/default.conf

# Copiar nuestra configuración
COPY nginx.conf /etc/nginx/conf.d/app.conf

# Copiar los archivos estáticos del frontend
COPY index.html /usr/share/nginx/html/
COPY styles.css /usr/share/nginx/html/
COPY hitos.html /usr/share/nginx/html/
COPY hitos.css /usr/share/nginx/html/
COPY hitos.js /usr/share/nginx/html/
COPY chart.umd.min.js /usr/share/nginx/html/
COPY formulario.patch.js /usr/share/nginx/html/
COPY Diseño_sin_título.svg /usr/share/nginx/html/
COPY .well-known/ /usr/share/nginx/html/.well-known/

EXPOSE 80
