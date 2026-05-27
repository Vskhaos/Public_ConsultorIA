FASES_POR_TIPO = {
    "pentesting_externo": [
        {
            "nombre": "OSINT",
            "descripcion": "Inteligencia de fuentes abiertas: subdominios, DNS, certificados, emails, tecnologías",
            "min_iteraciones": 3,
            "peso_tiempo": 0.10
        },
        {
            "nombre": "Reconocimiento",
            "descripcion": "Mapeo activo de superficie: puertos, servicios, banners, paths web",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Enumeración",
            "descripcion": "Identificación de versiones, tecnologías y configuraciones expuestas",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de vulnerabilidades",
            "descripcion": "Identificación de vulnerabilidades en los servicios encontrados",
            "min_iteraciones": 3,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Explotación controlada",
            "descripcion": "Verificación de vulnerabilidades críticas de forma controlada",
            "min_iteraciones": 2,
            "peso_tiempo": 0.15
        },
        {
            "nombre": "Documentación",
            "descripcion": "Consolidación de hallazgos y generación del informe",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "pentesting_interno": [
        {
            "nombre": "OSINT",
            "descripcion": "Inteligencia interna: AD/DNS, SMB/LDAP, GPO, shares, recursos de red",
            "min_iteraciones": 3,
            "peso_tiempo": 0.10
        },
        {
            "nombre": "Reconocimiento interno",
            "descripcion": "Mapeo activo de la red interna y activos disponibles",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Enumeración de servicios",
            "descripcion": "Identificación de servicios internos y configuraciones",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de vulnerabilidades",
            "descripcion": "Búsqueda de vulnerabilidades en servicios internos",
            "min_iteraciones": 3,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Movimiento lateral",
            "descripcion": "Análisis de posibilidades de escalada y movimiento lateral",
            "min_iteraciones": 2,
            "peso_tiempo": 0.15
        },
        {
            "nombre": "Documentación",
            "descripcion": "Consolidación de hallazgos y generación del informe",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "auditoria_web": [
        {
            "nombre": "OSINT",
            "descripcion": "Inteligencia abierta sobre la app: subdominios, tecnologías, repos públicos, fugas",
            "min_iteraciones": 3,
            "peso_tiempo": 0.10
        },
        {
            "nombre": "Reconocimiento web",
            "descripcion": "Análisis activo de la aplicación web y su superficie de ataque",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de autenticación",
            "descripcion": "Revisión de mecanismos de autenticación y autorización",
            "min_iteraciones": 2,
            "peso_tiempo": 0.15
        },
        {
            "nombre": "Análisis de vulnerabilidades web",
            "descripcion": "Búsqueda de OWASP Top 10 y otras vulnerabilidades comunes",
            "min_iteraciones": 3,
            "peso_tiempo": 0.30
        },
        {
            "nombre": "Análisis de API",
            "descripcion": "Revisión de endpoints de API y su seguridad",
            "min_iteraciones": 2,
            "peso_tiempo": 0.15
        },
        {
            "nombre": "Documentación",
            "descripcion": "Consolidación de hallazgos y generación del informe",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "cloud": [
        {
            "nombre": "Reconocimiento cloud",
            "descripcion": "Identificación de recursos y servicios cloud expuestos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de identidad y acceso",
            "descripcion": "Revisión de políticas IAM, roles y permisos excesivos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de configuración",
            "descripcion": "Revisión de configuraciones inseguras en servicios cloud",
            "min_iteraciones": 3,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de exposición de datos",
            "descripcion": "Identificación de buckets, bases de datos o recursos expuestos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Documentación",
            "descripcion": "Consolidación de hallazgos y generación del informe",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "cumplimiento_normativo": [
        {
            "nombre": "Inventario de activos",
            "descripcion": "Identificación y catalogación de activos en scope",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Revisión de políticas",
            "descripcion": "Análisis de políticas y procedimientos de seguridad",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Verificación técnica",
            "descripcion": "Comprobación técnica del cumplimiento de controles",
            "min_iteraciones": 3,
            "peso_tiempo": 0.35
        },
        {
            "nombre": "Análisis de gaps",
            "descripcion": "Identificación de brechas respecto al estándar objetivo",
            "min_iteraciones": 2,
            "peso_tiempo": 0.10
        },
        {
            "nombre": "Documentación",
            "descripcion": "Generación del informe de cumplimiento",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "rgpd_ens": [
        {
            "nombre": "Mapeo de datos personales",
            "descripcion": "Identificación de flujos y almacenamiento de datos personales",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de bases legales",
            "descripcion": "Revisión de consentimientos, contratos y bases legales del tratamiento",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Verificación de medidas técnicas",
            "descripcion": "Comprobación de cifrado, seudonimización y controles de acceso",
            "min_iteraciones": 3,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de derechos de interesados",
            "descripcion": "Revisión de procedimientos para ejercicio de derechos ARCO",
            "min_iteraciones": 2,
            "peso_tiempo": 0.15
        },
        {
            "nombre": "Análisis de gaps y riesgos",
            "descripcion": "Identificación de incumplimientos y evaluación de riesgos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.10
        },
        {
            "nombre": "Documentación",
            "descripcion": "Generación del informe de cumplimiento RGPD/ENS",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "phishing": [
        {
            "nombre": "Reconocimiento OSINT",
            "descripcion": "Recopilación de información sobre empleados y organización",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Diseño de campaña",
            "descripcion": "Preparación de pretextos y vectores de ataque social",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Ejecución controlada",
            "descripcion": "Lanzamiento de la campaña de phishing o ingeniería social",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de resultados",
            "descripcion": "Evaluación de tasas de éxito y vectores más efectivos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Documentación",
            "descripcion": "Generación del informe con métricas y recomendaciones",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ],
    "red_inalambrica": [
        {
            "nombre": "Reconocimiento wireless",
            "descripcion": "Identificación de redes inalámbricas y dispositivos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Análisis de cifrado",
            "descripcion": "Revisión de protocolos de cifrado WEP, WPA2, WPA3",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de autenticación",
            "descripcion": "Revisión de mecanismos de autenticación y portales cautivos",
            "min_iteraciones": 2,
            "peso_tiempo": 0.25
        },
        {
            "nombre": "Análisis de dispositivos",
            "descripcion": "Identificación de dispositivos mal configurados o vulnerables",
            "min_iteraciones": 2,
            "peso_tiempo": 0.20
        },
        {
            "nombre": "Documentación",
            "descripcion": "Generación del informe de seguridad wireless",
            "min_iteraciones": 1,
            "peso_tiempo": 0.10
        }
    ]
}

def obtener_fases(tipo: str) -> list:
    if tipo not in FASES_POR_TIPO:
        raise ValueError(f"Tipo de auditoría no soportado: {tipo}")
    return FASES_POR_TIPO[tipo]

def listar_tipos() -> list:
    return list(FASES_POR_TIPO.keys())
