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

public class InputStreamInStream extends InStream {

  static final int BUFSIZE = 16384;

  public InputStreamInStream(InputStream is) {
    this.is = is;
    b = new byte[BUFSIZE];
    ptr = end = offset = 0;
  }

  protected int overrun(int itemSize, int nItems, boolean wait) {
    if (itemSize > BUFSIZE)
      throw new ErrorException("InputStreamInStream overrun: max itemSize exceeded");

    if (end - ptr != 0)
      System.arraycopy(b, ptr, b, 0, end - ptr);

    offset += ptr;
    end -= ptr;
    ptr = 0;

    while (end < itemSize) {
      int n = 0;
      try {
        if (is.available() == 0) {
          if (!wait) {
            //System.out.println("read stop");
            break;
          } else if (blockCallback != null) {
            //System.out.println("read block");

            while (is.available() == 0) {
              blockCallback.blockCallback();
            }

            //System.out.println("read block done");
          }
        }
        //System.out.println("read " + wait);
        n = is.read(b, end, BUFSIZE - end);
        //System.out.println("read done");
      } catch (IOException e) {
        throw new ErrorException("Read error: " + e.getMessage());
      }
      if (n < 1) {
        if (n < 0) { throw new EndOfStream(); }
        if (n == 0) { return 0; }
      }
      end += n;
    }

    if (itemSize * nItems > end - ptr)
      nItems = (end - ptr) / itemSize;

    return nItems;
  }

  public final int pos() { return offset + ptr; }

  InputStream is;
  int offset;

  public InputStream getStream() { return is; }

  public void setBlockCallback(FdInStreamBlockCallback blockCallback_) {
    blockCallback = blockCallback_;
    //timeoutms = 0;
  }
  private FdInStreamBlockCallback blockCallback;
};
