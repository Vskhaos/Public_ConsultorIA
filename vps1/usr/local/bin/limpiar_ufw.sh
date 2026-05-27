#!/bin/bash

# Desactivar UFW
sudo ufw disable

# Restablecer las reglas de UFW sin solicitar confirmación
echo "y" | sudo ufw reset
