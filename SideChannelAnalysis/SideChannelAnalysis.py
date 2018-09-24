


file1="datos.txt"  # contiene en cada fila un mensaje de entrada del algoritmo y, a continuación, el texto cifrado de salida (formato hexadecimal).
file2="trazas.txt" # contiene en cada fila la señal de consumo de la ejecución del algoritmo en un dispositivo hardware

print ("PAC 1 - SCA Fichero de datos:  " + file1 )
print ("PAC 1 - SCA Fichero de trazas: " + file2)

def calc_SubBytes_round1 ( param ):
    # "Calculo el valor del primer byte a la salida de la transformacion SubBytes de la primera ronda del algoritmo para cada uno de los 256 posibles valores del primer byte de la clave secreta"
    for i in range(256):
        print (str(i)+" Calculo")
    return

def coeficiente_Pearson ( param ):
    # Calcular el coeficiente de correlación de Pearson entre los datos calculados en el punto 2 y las señales proporcionadas en el archivo trazas.txt.

    return





#with open(file1, "rb") as f:
#    byte = f.read(1)
#    while byte:
        # Do stuff with byte.
#        byte = f.read(1)
calc_SubBytes_round1 (1)

#De las 256 curvas de correlación obtenidas, una por cada hipótesis del valor del primer byte de la clave, ordenarlas en función de la amplitud del mayor pico de correlación observado. Con esto se establecerá un ránking de probabilidad del valor de la clave.



#5. Si se ha hecho correctamente, el valor del primer byte de la clave corresponde Si se ha hecho correctamente, el valor del primer byte de la clave corresponde a la curva con el pico de mayor amplitud.
#6. Repetir los pasos anteriores para los restantes 15 bytes.