using System;

namespace Nulah.Roomba 
{
    public interface ILogger
    {
        void Debug(string logMessage, string logGroup);
        void Debug(string logMessage);
        void Info(string logMessage);
        void Error(string logMessage, Exception e);
        bool IsDebugEnabled { get; }
    }

    public class ConsoleLogger : ILogger
    {
        public ConsoleLogger(bool isDebugEnabled)
        {
            IsDebugEnabled = isDebugEnabled;
        }
        public void Debug(string logMessage, string logGroup)
        {
            if( IsDebugEnabled )
                Log($"DEBUG [{logGroup}] {logMessage}");
        }

        public void Debug(string logMessage)
        {
            if( IsDebugEnabled )
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

        public bool IsDebugEnabled { get; }

        private void Log(string logMessage)
        {
            Console.WriteLine($"{DateTime.Now:dd-MM-yyyy HH:mm:ss,fff}: {logMessage}");
        }
    }
}
