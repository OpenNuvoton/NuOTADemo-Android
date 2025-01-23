package com.nuvoton.otaserver.utility;

/**
 * Created by cchsu20 on 29/09/2017.
 */

public class IntegerBuffer {
    private int position, limit, size;
    private int[] data;
    private IntegerBuffer(){}
    public static IntegerBuffer allocate(int size){
        IntegerBuffer buffer = new IntegerBuffer();
        buffer.data = new int[size];
        buffer.limit = size;
        buffer.size = size;
        buffer.position = 0;
        return buffer;
    }

    public void flip(){
        this.limit = this.position;
        this.position = 0;
    }

    public int limit(){
        return this.limit;
    }

    public void put(int data){
        this.data[position] = data;
        this.position++;
    }

    public int[] get(){
        int size = this.limit - this.position;
        int[] temp = new int[size];
        System.arraycopy(this.data, position, temp, 0, size);
        return temp;
    }

    public void clear(){
        this.position = 0;
        this.limit = this.size;
        for (int i=0; i<this.size; i++){
            this.data[i] = 0;
        }
    }
}
