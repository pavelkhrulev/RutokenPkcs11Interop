using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RutokenPkcs11Interop.Common
{
    public class PinPolicy
    {
        public bool? PinContainsLowerLetter { get; set; }
        public bool? PinContainsUpperLetter { get; set; }
        public bool? PinContainsDigit { get; set; }
        public bool? PinContainsSpecChar { get; set; }
        public bool? RestrictOneCharPin { get; set; }
        public bool? AllowDefaultPinUsage { get; set; }
        public bool? AllowChangePinPolicy { get; set; }
        public bool? RemovePinPolicyAfterFormat { get; set; }
        public byte? MinPinLength { get; set; }
        public byte? PinHistoryDepth { get; set; }

        public static implicit operator bool(PinPolicy value)
        {
            if (value.PinContainsLowerLetter != null)
                return true;
            if (value.PinContainsUpperLetter != null)
                return true;
            if (value.PinContainsDigit != null)
                return true;
            if (value.PinContainsSpecChar != null)
                return true;
            if (value.RestrictOneCharPin != null)
                return true;
            if (value.AllowDefaultPinUsage != null)
                return true;
            if (value.AllowChangePinPolicy != null)
                return true;
            if (value.RemovePinPolicyAfterFormat != null)
                return true;
            if (value.MinPinLength != null)
                return true;
            if (value.PinHistoryDepth != null)
                return true;
            return false;
        }
    }
}
