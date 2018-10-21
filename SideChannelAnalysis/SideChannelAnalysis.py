#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Practica 1 PAC 1: Side channel analysis de algoritmos criptográficos


Requisitos en ubuntu 18:
sudo apt install python3-matplotlib python3-path python3-distutils python3-scipy python3-numpy python3-pycryptodome python python-tk python-path 

pip install path.py numpy scipy matplotlib

"""

import os, sys, datetime, path
import random, numpy, scipy.stats, matplotlib.pyplot as plt
import binascii


#from binascii import unhexlify

__author__ = "Yaco Melian"
__copyright__ = ""
__credits__ = ["https://gist.github.com/raullenchai/2920069", "https://www.expobrain.net/2013/07/29/hamming-weights-python-implementation/", "Yaco Melian"]
__version__ = "0.0.1"
__maintainer__ = "Yaco Melian"
__email__ = "yacomelian@gmail.com"
__status__ = "Production"

### Variables de trabajo
workpath = os.getcwd() + "/"
mostrargrafica = True
cargarficheros = True
sobreescribirficheros = False
 
### Constantes del programa
# Tabla de búsqueda de operación SubBytes
sBox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# Funcion para AES SubBytes, descarto su uso por optimizacion
def subBytes( value ):
    return sBox[value]

# Funcion para calcular el peso de hamming (numero de bits a 1 en un byte)
# Origen: https://www.expobrain.net/2013/07/29/hamming-weights-python-implementation/
def hamming_weight( x ):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((x * 0x0101010101010101) & 0xffffffffffffffff ) >> 56

# Resuelve preguntas de si, no    
def query_yes_no(question, default="no"):
    """Realiza na pregunta de si o no via input() y devuelve la respuesta.
    "question" es una cadena que se mostrara al usuario.
    "default" es la respuesta predeterminada
    La respuesta se devuelve como True para si, False para no.
    """
    valid = {"si": True, "s": True, 
             "yes":True, "y" :True,
             "no": False, "n": False}
    if default is None:
        prompt = " [s/n] "
    elif default == "si":
        prompt = " [S/n] "
    elif default == "no":
        prompt = " [s/N] "
    else:
        raise ValueError("respuesta predeterminada incorrecta: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        try:
            choice = raw_input().lower()
        except:
            choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Por favor, responda con 'si' o 'no' "
                             "(or 's' o 'n').\n")

# Funcion principal de calculo
def sca (ldatos, ltraza):
    # Para operaciones posteriores, calculo tamaños de los ficheros
    numberofmessages = len (ldatos)         # Número de mensajes
    numberoftraces = len(ltraza)            # Longitud total de la línea de trazas
    lenoftraces = int(len(ltraza[0])/2)     # Número total de trazas
    numberofkeys = 256

    #Convierto fichero de trazas de texto a enteros
    # Reservo una matriz primero, optimizacion
    ti = numpy.zeros((numberoftraces,lenoftraces))
    for i in range(0,numberoftraces):
        ti[i] = ltraza[i].split()
    
    # Guardamos la matrix transpuesta para calcular el coeficiente.
    ti_trans = numpy.matrix.transpose(ti)
    key = [ 0 ] * 16            # Reservo un vector para almacenar la clave
    instant = [ 0 ] * 16        # Reservo un vector para almacenar el instante de mayor correlación
    qpi = [0] * 16              # Vector para almacenar todas las matrices de correlación de cada valor de clave
    
    for bytemensaje in range (0,32,2):  # Para cada byte de entrada del mensaje
        cnt=int((bytemensaje/2)+1)  # Cuento el byte que estoy procesando
        print (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S ") + "Procesando byte " + str(cnt) + " de 16. ")

        # Este if es para controlar cuando leo los resultados de los ficheros, o vuelvo a recalcular todo.
        filename = workpath + "result_" + str(cnt) + ".matrix.npy"
        filecache = path.Path(filename).isfile();               # Compruebo si el fichero con resultados guardados existe
        if (not (cargarficheros and filecache)):
            pi = numpy.zeros((numberofkeys,lenoftraces)) # Matriz donde almaceno los coeficientes de pearson (256 posibles claves x el numero de trazas
            for valorclave in range(0x00,0x100): # Para cada posible clave
                xi = [ valorclave ] * numberofmessages  # Inicializo vector para almacenar 
                si = [ 0 ] * numberofmessages           # Inicializo vector SubBytes
                hi = [ 0 ] * numberofmessages           # Inicializo vector pesos de Hamming

                for mi in range (0,len(ldatos)):
                    # Realizo la funcion XOR del valor clave (ya contenido en xi) con el byte correspondiente del mensaje
                    xi[mi] ^=  int(ldatos[mi][bytemensaje:bytemensaje+2],16)
                    # Calculo Subbytes
                    si[mi] = sBox[xi[mi]]
                    # Calculo peso de hamming
                    hi[mi] = hamming_weight (si[mi])
                    # Con esto, ya tengo los datos de entrada, para calcular pearson, tengo que relacionar los pesos de hamming frente a las trazas
                    # Solo para debug, mostrar:
                    #print ("XOR: ",valorclave," ^ ", ldatos[mi][bytemensaje:bytemensaje+2], " = ", xi[mi], " SubBytes: ", si[mi], " Peso Hamming: ", hi[mi])
                
                # Calculo el coeficiente de pearson entre los pesos de haming y cada una de las trazas
                for t in range (0, lenoftraces):
                    # Tomo el valor de correlación de pearson, que se devuelve como el primer valor de esta función, por eso [0]
                    pi[valorclave][t] = scipy.stats.pearsonr(ti_trans[t],hi)[0]
            # Para poder optimizar la ejecución o la revisión de resultados, guardo el resultado de los calculos en un fichero
            if (not filecache or sobreescribirficheros):    # Si elijo sobreescribir los datos, o el fichero de resultados no existe
                numpy.save(filename, pi)

        else:  # Si existe el fichero, lo leo directamente, no vuelvo a realizar los calculos     
            #print ("Cargo fichero ", cnt, " de 16")
            pi = numpy.load(filename)
            
        # Busco el valor de mayor correlación
        momento = numpy.argmax(pi) % lenoftraces     # Posición (instante) de correlación máxima
        instant[cnt-1] = momento        # Vector con instantes
        
        # Transpongo la matriz porque la funcion busca los máximos por fila, así facilito el cálculo
        pi_trans = numpy.matrix.transpose(pi)
        # La clave sera el punto de mayor correlacion, modulo 256, porque son el numero de posibles claves
        cmax = numpy.argmax(pi_trans)%numberofkeys   # Clave del máximo
        key[cnt-1] = cmax               # Vector con claves
        qpi[cnt-1] = pi                 # Vector con correlaciones, para gráficas

        # El momento nos indica un valor de tiempo, de cuando fue procesada esa clave, debe ocurrir, que cada byte de
        # clave se haya calculado en su momento, es decir, el primer byte de clave, es el primero que aparece en las trazas
        print ("Maximo encontrado en el momento  :", momento, "Clave : ", key[cnt-1] )

    return ( key, qpi)

def comprobar_clave (ldatos, skey):
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from binascii import hexlify,unhexlify
    numberoftests = 5                   # Al azar elijo el número de pruebas a realizar
    for i in range (0,numberoftests):      # Hago múltiples comprobaciones
        nummensaje = random.randint(0,len(ldatos))   # Elijo mensaje aleatorio de los 5mill
        mensajeacifrar = ldatos[nummensaje][:32]  #   ldatos[nummensaje][:32]
        hexacifrar = unhexlify(ldatos[nummensaje][:32])  #   ldatos[nummensaje][:32]
        cifradocorrecto = ldatos[nummensaje][32:].rstrip()
        mensajecifrado = cifradocorrecto
        #key = unhexlify(skey)
        #key = get_random_bytes(16)
#        print (key)
        key = binascii.hexlify(bytearray(skey))
        print (key)
        key = unhexlify(key)
        print (key)
        cypher = AES.new(key, AES.MODE_ECB)
        print ("Mensaje a cifrar  :", mensajeacifrar)
        print ("Hex a cifrar      :", hexacifrar)
        print ("Clave             :", key, " - ")
        print ("Cifrado correcto  :", cifradocorrecto)
        mensajecifrado = str( hexlify(cypher.encrypt(hexacifrar)).decode("utf-8") ).upper()
        print ("Mensaje cifrado   :", mensajecifrado)
        if (mensajecifrado == cifradocorrecto):
            print ("La clave es correcta")
        else:
            print ("Error: la clave es incorrecta")


    #Clave CAFEBABEDEADBEEFBADAB000FFAAAAAA
    

    #cipher = unhexlify('9B2808B4743D822697AD55243F956A39')
    #aes = AES.new(key, AES.MODE_CBC, iv)
 
    #print ( aes.decrypt(cipher.decode('hex')))
    

def main ():
    
    # Defino los ficheros de entrada
    str_fdatos= workpath + "datos.txt" # contiene en cada fila un mensaje de entrada del algoritmo y, a continuación, el texto cifrado de salida (formato hexadecimal).
    str_ftraza= workpath + "trazas.txt" # contiene en cada fila la señal de consumo de la ejecución del algoritmo en un dispositivo hardware

    if (path.Path(str_fdatos).isfile() and  path.Path(str_ftraza).isfile()):
    # Toma de datos para ejecución
        global cargarficheros, sobreescribirficheros, mostrargrafica
        cargarficheros = query_yes_no("¿Usar ficheros?", "si")
        if (not cargarficheros):
            sobreescribirficheros = query_yes_no("¿Desea sobreescribir los ficheros (No para mantener los actuales)?")
        mostrargrafica = query_yes_no("¿Desea visualizar graficas?")
        comprobarclave = query_yes_no("¿Desea comprobar la clave?","si")

        # Leo ambos ficheros y los almaceno en memoria
        fdatos=open(str_fdatos,"r")
        ftraza=open(str_ftraza,"r")
        ldatos = fdatos.readlines()
        ltraza = ftraza.readlines()
    
        # Inicio el análisis
        result = sca(ldatos,ltraza)         # Devuelve un array con 2 objetos 0: clave, 1:Matrices para las gráficas

         # Muestro la clave obtenida
        print ("")
        print ("Valor de la clave INT: ",result[0])
        print ("Valor de la clave HEX: ", str(binascii.hexlify(bytearray(result[0])).upper()))
        print ("")

        # Dibujar las gráficas
        if (mostrargrafica == True):
            print ("Dibujando gráficas...")
            for i in range (len(result[1])):
                plt.figure("Evaluación de clave para Byte " + str(i+1))
                plt.plot(result[1][i])
                plt.xlabel("Evaluación de clave")
                plt.ylabel("Coeficiente de Pearson")
                plt.title ("Correlación de claves " + str(i+1))
                plt.pause(0.05)
            plt.show()
            plt.close

        if (comprobarclave == True):
            comprobar_clave (ldatos, result[0])
    else:
        print ("Error: No existen los archivos de entrada de datos en la ruta:")
        print (workpath)
        print ("Por favor, compruebelo.")

if sys.version_info[0] != 3:
    print("This script requires Python version 3")
    sys.exit(1)
    
main()