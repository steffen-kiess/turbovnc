/* Copyright (C) 2021 Steffen Kieß
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

package com.turbovnc.rdr;

import java.io.*;

public class OutputStreamOutStream extends OutStream {

  static final int BUFSIZE = 16384;

  public OutputStreamOutStream(OutputStream out) {
    this.os = out;
    b = new byte[BUFSIZE];
    ptr = offset = start = 0;
    end = start + BUFSIZE;
  }

  public int length() {
    return offset + ptr - start;
  }

  public void flush() {
    try {
      if (start < ptr) {
        //System.out.println("write");
        os.write(b, start, ptr - start);
        //System.out.println("write flush");
        //System.out.println("write done " + (ptr - start));
        offset += ptr - start;
      }
      ptr = start;
      os.flush();
    } catch (IOException e) {
      throw new ErrorException("Write error: " + e.getMessage());
    }
  }

  protected int overrun(int itemSize, int nItems) {
    if (itemSize > BUFSIZE)
      throw new ErrorException("OutputStreamOutStream overrun: max itemSize exceeded");

    flush();

    if (itemSize * nItems > end - ptr)
      nItems = (end - ptr) / itemSize;

    return nItems;
  }

  private OutputStream os;
  private int start;
  private int offset;

  public OutputStream getStream() { return os; }
}
