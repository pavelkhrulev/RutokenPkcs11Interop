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
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadOnly))
                {
                    bool res;
                    try
                    {
                        res = session.PinPolicySupports(CKU.CKU_USER);
                    } catch (Exception ex) {
                        Console.WriteLine(ex.Message);
                        return;
                    }

                    Console.WriteLine("Pin policy supports by token: " + (res ? "true" : "false"));
                }
            }
        }

        /// <summary>
        /// GetPinPolicy test.
        /// </summary>
        [Test()]
        public void _HL_35_02_GetPinPolicy_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadOnly))
                {
                    try
                    {
                        if (!session.PinPolicySupports(CKU.CKU_USER)) {
                            Console.WriteLine("Token doesn't support PIN-policies");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                        return;
                    }

                    PinPolicy pinPolicy = session.GetPinPolicy(CKU.CKU_USER);

                    Console.WriteLine("Min PIN Length: " + pinPolicy.MinPinLength);
                    Console.WriteLine("PIN history depth: " + pinPolicy.PinHistoryDepth);
                    Console.WriteLine("Allow default PIN-code usage: " + pinPolicy.AllowDefaultPinUsage);
                    Console.WriteLine("PIN requeres digits: " + pinPolicy.PinContainsDigit);
                    Console.WriteLine("PIN requeres uppercase chars: " + pinPolicy.PinContainsUpperLetter);
                    Console.WriteLine("PIN requeres lowercase chars: " + pinPolicy.PinContainsLowerLetter);
                    Console.WriteLine("PIN requeres spec chars: " + pinPolicy.PinContainsSpecChar);
                    Console.WriteLine("PIN requeres different char usage: " + pinPolicy.RestrictOneCharPin);
                    Console.WriteLine("PIN policy is modifiable by Admin: " + pinPolicy.AllowChangePinPolicy);
                    Console.WriteLine("PIN policy will be deleted after formating: " + pinPolicy.RemovePinPolicyAfterFormat);
                }
            }
        }

        /// <summary>
        /// SetPinPolicy test.
        /// </summary>
        [Test()]
        public void _HL_35_03_SetPinPolicy_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);
                    try
                    {
                        if (!session.PinPolicySupports(CKU.CKU_USER))
                        {
                            Console.WriteLine("Token doesn't support PIN-policies");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
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
