using System;

namespace Nulah.Roomba 
{
    public interface ILogger
    {
        void Debug(string logMessage, string logGroup);
        void Debug(string logMessage);
        void Info(string logMessage);
        void Error(string logMessage, Exception e);
    }

    public class ConsoleLogger : ILogger
    {
        public void Debug(string logMessage, string logGroup)
        {
            Log($"DEBUG [{logGroup}] {logMessage}");
        }

        public void Debug(string logMessage)
        {
            Log( $"DEBUG {logMessage}");
        }

        public void Info(string logMessage)
        {
            Log( $"INFO  {logMessage}");
        }

        public void Error(string logMessage, Exception e)
        {
            Log( $"ERROR {logMessage}: {e?.StackTrace}");
        }

        private void Log(string logMessage)
        {
            Console.WriteLine($"{DateTime.Now:dd-MM-yyyy HH:mm:ss,fff}: {logMessage}");
        }
    }
}
