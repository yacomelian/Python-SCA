#!/usr/bin/env python
"""Practica 1 PAC 1: Side channel analysis de algoritmos criptográficos

"""

import os, sys, datetime, path
import numpy, scipy.stats, matplotlib.pyplot as plt
import binascii, Crypto

#from Crypto.Cipher import AES
#from binascii import unhexlify

__author__ = "Yaco Melian"
__copyright__ = ""
__credits__ = ["https://gist.github.com/raullenchai/2920069", "https://www.expobrain.net/2013/07/29/hamming-weights-python-implementation/", "Yaco Melian"]
__version__ = "0.0.1"
__maintainer__ = "Aymedeyacoran Melian Suarez"
__email__ = "yacomelian@gmail.com"
__status__ = "Production"

### Variables de trabajo
workpath = os.getcwd() #"C:/Users/zzz/OneDrive/Documentos/00 - UOC/09 Seminarios en empresa (casos B) aula 1/PEC/"
#workpath1 = os.path.realpath(__file__)
mostrargrafica = True
cargarficheros = True
sobreescribirficheros = False
 


### Constantes del programa
# Tabla de búsqueda de operación SubBytes
#sBox    = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
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

    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"si": True, "s": True, 
             "no": False, "n": False}
    if default is None:
        prompt = " [s/n] "
    elif default == "si":
        prompt = " [S/n] "
    elif default == "no":
        prompt = " [s/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

# Funcion principal de calculo
def sca (ldatos, ltraza):
    # Para operaciones posteriores, calculo tamaños de los ficheros
    numberofmessages = len (ldatos)
    numberoftraces = len(ltraza)
    lenoftraces = int(len(ltraza[0])/2)

    #Convierto fichero de trazas de texto a enteros
    # Reservo una matriz primero, optimizacion
    ti = numpy.zeros((numberoftraces,lenoftraces))
    for i in range(0,numberoftraces):
        ti[i] = ltraza[i].split()
    
    # Guardamos la matrix transpuesta para calcular el coeficiente.
    ti_trans = numpy.matrix.transpose(ti)
    key = [ 0 ] * 16
    instant = [ 0 ] * 16
    qpi = [0] * 16
    
    for bytemensaje in range (0,32,2):
        
        # Para cada valor posible de la clave
        # Almaceno los coeficientes, para cada byte de la posible clave, tendre 256 vectores(arrays), cada vector con 480 componentes, y esos componentes serán el valor de los coeficientes de pearson
        cnt=int((bytemensaje/2)+1)  # Cuento el byte que estoy procesando
        print (datetime.datetime.now().strftime("%Y-%m-%d %H:%M ") + "Procesando byte " + str(cnt) + " de 16. ")

        # Este if es para controlar cuando leo los resultados de los ficheros, o vuelvo a recalcular todo.
        filename = workpath + "result_" + str(cnt) + ".matrix.npy"
        filecache = path.Path(filename).isfile();               # Compruebo si el fichero con resultados guardados existe
        if (not (cargarficheros and filecache)):
            pi = numpy.zeros((256,lenoftraces)) # Matriz donde almaceno los coeficientes de pearson (256 posibles claves x el numero de trazas
            for valorclave in range(0x00,0xFF): # Para cada posible clave
                # Para cada mensaje
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
                    #    print ("XOR: ",valorclave," ^ ", ldatos[mi][bytemensaje:bytemensaje+2], " = ", xi[mi], " SubBytes: ", si[mi], " Peso Hamming: ", hi[mi])
                
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
        max = numpy.max(pi)         # Valor de correlación máximo en momento (tiempo)
        min = numpy.min(pi)         # Valor de correlación negativa máxima
        mmax = numpy.argmax(pi)     # Posición en el máximo
        mmin = numpy.argmin(pi)     # Posición en el mínimo
        if (abs(max) > abs(min)):   # Aquí valoro el momento de mayor correlación
            momento = mmax % 480    
        else:
            momento = mmin % 480
        instant[cnt-1] = momento        # Vector con instantes
        
        # Transpongo la matriz porque la funcion busca los máximos por fila, así facilito el cálculo
        pi_trans = numpy.matrix.transpose(pi)
        # La clave estará sera el punto de mayor correlacion, modulo 256, porque son el numero de posibles claves
        max = numpy.max(pi_trans)       # Valor de correlación máximo en clave
        min = numpy.min(pi_trans)       # Valor de correlación negativa máxima de clave 
        cmax = numpy.argmax(pi_trans)   # Clave del máximo
        cmin = numpy.argmin(pi_trans)   # Clave del mínimo
        if (abs(max) > abs(min)):       # Punto de mayor correlación (será la clave)
            clave = cmax % 256
        else:
            clave = cmin % 256
        key[cnt-1] = clave%256          # Vector con claves
        qpi[cnt-1] = pi
        # El momento nos indica un valor de tiempo, de cuando fue procesada esa clave, debe ocurrir, que cada byte de
        # clave se haya calculado en su momento, es decir, el primer byte de clave, es el primero que aparece en las trazas
        print ("Maximo encontrado en el momento  :", momento, "Clave : ", key[cnt-1] )

    sca = (
        key,
        instant,
        qpi
    )

    return sca

def main ():
    
    # Defino los ficheros de entrada
    str_fdatos= workpath + "/datos.txt" # contiene en cada fila un mensaje de entrada del algoritmo y, a continuación, el texto cifrado de salida (formato hexadecimal).
    str_ftraza= workpath + "/trazas.txt" # contiene en cada fila la señal de consumo de la ejecución del algoritmo en un dispositivo hardware

    if (path.Path(str_fdatos).isfile() and  path.Path(str_ftraza).isfile()):
    # Toma de datos para ejecución
        global cargarficheros, sobreescribirficheros, mostrargrafica
        cargarficheros = query_yes_no("¿Usar ficheros?")
        if (not cargarficheros):
            sobreescribirficheros = query_yes_no("¿Desea sobreescribir los ficheros (No para mantener los actuales)?")
        mostrargrafica = query_yes_no("¿Desea visualizar graficas?")

        # Leo ambos ficheros y los almaceno en memoria
        fdatos=open(str_fdatos,"r")
        ftraza=open(str_ftraza,"r")



        ldatos = fdatos.readlines()
        ltraza = ftraza.readlines()
    

        # Inicio el análisis
        result = sca(ldatos,ltraza)

         # Muestro la clave obtenida
        print ("")
        print ("Valor de la clave INT: ",result[0])
        print ("Valor de la clave HEX: ", str(binascii.hexlify(bytearray(result[0])).upper()))
        print ("")

        # Dibujar las gráficas
        if (mostrargrafica == True):
            print ("Dibujando gráficas...")
            for i in range (len(result[2])):
                plt.figure("Evaluación de clave para Byte " + str(i+1))
                plt.plot(result[2][i])
                plt.xlabel("Evaluación de clave")
                plt.ylabel("Coeficiente de Pearson")
                plt.title ("Correlación de claves " + str(i+1))
                plt.pause(0.05)
            plt.show()
            plt.close

    #CAFEBABEDEADBEEFBADAB0000AAAAAAA
    #CAFEBABEDEADBEEFBADAB0000AAAAAAA

    #cipher = unhexlify('9B2808B4743D822697AD55243F956A39')
    #aes = AES.new(key, AES.MODE_CBC, iv)
 
    #print ( aes.decrypt(cipher.decode('hex')))
    else:
        print ("Error: No existen los archivos de entrada de datos en la ruta:")
        print (workpath)
        print ("Por favor, compruebelo.")
    
main()

'''
De las 256 curvas de correlación obtenidas, una por cada hipótesis del valor del primer byte de la clave, ordenarlas en función de la amplitud del mayor pico de correlación observado. 
Con esto se establecerá un ránking de probabilidad del valor de la clave.
'''



#5. Si se ha hecho correctamente, el valor del primer byte de la clave corresponde Si se ha hecho correctamente, el valor del primer byte de la clave corresponde a la curva con el pico de mayor amplitud.
#6. Repetir los pasos anteriores para los restantes 15 bytes.
