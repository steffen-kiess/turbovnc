/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright (C) 2012 Brian P. Hinz
 * Copyright (C) 2012 D. R. Commander.  All Rights Reserved.
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

// -=- Socket - abstract base-class for any kind of network stream/socket

package com.turbovnc.network;

import com.turbovnc.rdr.*;
import java.nio.channels.*;

public abstract class Socket {

  public InStream inStream() { return instream; }
  public OutStream outStream() { return outstream; }

  // if shutdown() is overridden then the override MUST call on to here
  public void shutdown() { isShutdown = true; }
  public abstract void close();
  public final boolean isShutdown() { return isShutdown; }

  // information about this end of the socket
  public abstract int getMyPort();

  // information about the remote end of the socket
  public abstract String getPeerAddress();  // a string e.g. "192.168.0.1"
  public abstract String getPeerName();
  public abstract int getPeerPort();
  public abstract String getPeerEndpoint();  // <address>::<port>

  // Is the remote end on the same machine?
  public abstract boolean sameMachine();

  // Was there a "?" in the ConnectionFilter used to accept this Socket?
  public void setRequiresQuery() { queryConnection = true; }
  public final boolean requiresQuery() { return queryConnection; }

  protected Socket() {
    instream = null;  outstream = null;  ownStreams = false;
    isShutdown = false;  queryConnection = false;
  }

  protected Socket(InStream i, OutStream o, boolean own) {
    instream = i;  outstream = o;  ownStreams = own;
    isShutdown = false;  queryConnection = false;
  }

  protected InStream instream;
  protected OutStream outstream;
  boolean ownStreams;
  boolean isShutdown;
  boolean queryConnection;
}
