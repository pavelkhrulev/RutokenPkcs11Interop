﻿using System;
using System.Collections.Generic;
using System.Linq;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI81;
using Net.Pkcs11Interop.HighLevelAPI;

using Net.RutokenPkcs11Interop.HighLevelAPI;
using LLA = Net.RutokenPkcs11Interop.LowLevelAPI81;

namespace Net.RutokenPkcs11Interop.HighLevelAPI81
{
    public class RutokenPkcs11Library : Pkcs11Library, IRutokenPkcs11Library
    {
        protected LLA.RutokenPkcs11Library _pkcs11LibraryExtention = null;

        protected RutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath)
            : base(factories, libraryPath)
        {

        }

        public RutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
            : base(factories, libraryPath, appType)
        {
            _pkcs11LibraryExtention = new LLA.RutokenPkcs11Library(libraryPath);
        }

        public RutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
            : base(factories, libraryPath, appType, initType)
        {
            _pkcs11LibraryExtention = new LLA.RutokenPkcs11Library(libraryPath);
        }

        public List<IRutokenSlot> GetRutokenSlotList(SlotsType slotsType)
        {
            return GetSlotList(slotsType).Select(slot => (IRutokenSlot)slot).ToList();
        }

        public void FreeBuffer(IntPtr buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = _pkcs11LibraryExtention.C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }
    }
}
