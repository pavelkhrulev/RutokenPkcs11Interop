using System;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    /// <summary>
    /// GetPinPolicy, SetPinPolicy, PinPolicySupports tests.
    /// </summary>
    [TestFixture()]
    public class _HL_35_PinPolicyTest
    {

        /// <summary>
        /// SupportsPinPolicy test.
        /// </summary>
        [Test()]
        public void _HL_35_01_SupportsPinPolicy_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    bool res;
                    try
                    {
                        res = session.PinPolicySupports(CKU.CKU_USER);
                    } catch (Exception ex) {
                        Console.WriteLine(ex.Message, "\n");
                        return;
                    }

                    Console.WriteLine("Pin policy supports by token: " + (res ? "true" : "false"), "\n");
                }
            }
        }

        /// <summary>
        /// GetPinPolicy test.
        /// </summary>
        [Test()]
        public void _HL_35_02_GetPinPolicy_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    try
                    {
                        if (!session.PinPolicySupports(CKU.CKU_USER)) {
                            Console.WriteLine("Token doesn't support PIN-policies\n");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message, "\n");
                        return;
                    }

                    PinPolicy pinPolicy = session.GetPinPolicy(CKU.CKU_USER);

                    Console.WriteLine("Min pin Length: " + pinPolicy.MinPinLength + "\n");
                    Console.WriteLine("History depth: " + pinPolicy.PinHistoryDepth + "\n");
                    Console.WriteLine("Allow default Pin-code usage: " + ((bool) pinPolicy.AllowDefaultPinUsage ? "true" : "false") + "\n");
                    Console.WriteLine("Pin-code requeres digits: " + ((bool)pinPolicy.PinContainsDigit ? "true" : "false") + "\n");
                    Console.WriteLine("Pin-code requeres uppercase chars: " + ((bool)pinPolicy.PinContainsUpperLetter ? "true" : "false") + "\n");
                    Console.WriteLine("Pin-code requeres lowercase chars: " + ((bool)pinPolicy.PinContainsLowerLetter ? "true" : "false") + "\n");
                    Console.WriteLine("Pin-code requeres spec chars: " + ((bool)pinPolicy.PinContainsSpecChar ? "true" : "false") + "\n");
                    Console.WriteLine("Pin-code requeres different char usage: " + ((bool)pinPolicy.RestrictOneCharPin ? "true" : "false") + "\n");
                    Console.WriteLine("PIN-policy is modifiable by Admin: " + ((bool)pinPolicy.AllowChangePinPolicy ? "true" : "false") + "\n");
                    Console.WriteLine("PIN-policy will be deleted after formating: " + ((bool)pinPolicy.RemovePinPolicyAfterFormat ? "true" : "false") + "\n");
                }
            }
        }

        /// <summary>
        /// SetPinPolicy test.
        /// </summary>
        [Test()]
        public void _HL_35_03_SetPinPolicy_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);
                    try
                    {
                        if (!session.PinPolicySupports(CKU.CKU_USER))
                        {
                            Console.WriteLine("Token doesn't support PIN-policies\n");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message, "\n");
                        return;
                    }

                    PinPolicy pinPolicy = new PinPolicy();
                    pinPolicy.MinPinLength = 0;
                    pinPolicy.PinHistoryDepth = 0;
                    //pinPolicy.AllowDefaultPinUsage = true;
                    pinPolicy.PinContainsDigit = false;
                    pinPolicy.PinContainsUpperLetter = false;
                    pinPolicy.PinContainsLowerLetter = false;
                    pinPolicy.PinContainsSpecChar = false;
                    pinPolicy.RestrictOneCharPin = false;
                    //pinPolicy.AllowChangePinPolicy = true;
                    //pinPolicy.RemovePinPolicyAfterFormat = true;

                    session.SetPinPolicy(pinPolicy, CKU.CKU_USER);

                    session.Logout();
                }
            }
        }
    }
}
