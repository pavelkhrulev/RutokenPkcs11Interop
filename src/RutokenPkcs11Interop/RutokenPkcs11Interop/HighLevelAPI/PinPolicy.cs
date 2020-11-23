using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class PinPolicy
    {
        public bool PinContainsLowerLetter { get; set; }
        public bool PinContainsUpperLetter { get; set; }
        public bool PinContainsDigit { get; set; }
        public bool PinContainsSpecChar { get; set; }
        public bool RestrictOneCharPin { get; set; }
        public bool AllowDefaultPinUsage { get; set; }
        public bool AllowChangePinPolicy { get; set; }
        public bool RemovePinPolicyAfterFormat { get; set; }
        public byte MinPinLength { get; set; }
        public byte PinHistoryDepth { get; set; }
    }
}
